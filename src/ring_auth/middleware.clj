(ns ring-auth.middleware
  (:import
    [java.util UUID])
  (:require
    [clj-time.core :as time]
    [clj-time.coerce :as coerce]
    [clojure.tools.logging :as log]
    [ring.middleware.session.store :as store]
    [ring.middleware.session.memory :as memory]))

(def ^:private auth-cookie "auth-id")

(defn- secure? [request]
  (or (= :https (:scheme request))
      (= "https" (get-in request [:headers "x-forwarded-proto"]))))

(defn- timed-out? [{:keys [max-age idle-timeout last-access created-at]}]
  (or
    (time/after? (time/now) (time/plus (coerce/from-long created-at) (time/seconds max-age)))
    (time/after? (time/now) (time/plus (coerce/from-long last-access) (time/seconds idle-timeout)))))

(defn- essential-request [request]
  (select-keys request [:uri :remote-addr :headers]))

(defn- handle-insecure-session! [request session-store auth-session-id]
  (log/errorf
    "Passed auth-id %s with insecure request %s.  Deleting authorization-session." auth-session-id (essential-request request))
  (store/delete-session session-store auth-session-id)
  nil)

(defn- handle-unknown-session! [request auth-session-id]
  (log/errorf "Unknown auth-id %s in request %s" auth-session-id (essential-request request)))

(defn- handle-timed-out-session! [request session-store auth-session-id]
  (store/delete-session session-store auth-session-id)
  nil)

(defn- read-auth-session [request session-store auth-session-id]
  (if-let [auth-session (store/read-session session-store auth-session-id)]
    (if (secure? request)
      (if (not (timed-out? auth-session))
        auth-session
        (handle-timed-out-session! request session-store auth-session-id))
      (handle-insecure-session! request session-store auth-session-id))
    (handle-unknown-session! request auth-session-id)))

(defn make-auth-session
  "Create an authorization session with a given idle-timeout and max-age expressed in seconds"
  [idle-timeout max-age]
  { :csrf-token   (str (UUID/randomUUID))
    :idle-timeout idle-timeout
    :max-age      max-age
    :last-access  (coerce/to-long (time/now))
    :created-at   (coerce/to-long (time/now)) })

(defn wrap-auth-session
  "Associates an :auth-session key to the request map an authorization cookie is passed in.  To set an authorization session, simply provide an :auth-session key in the response map (set to nil to delete).

  An authorization session is a map with at least the following keys:

    :csrf-token     - A token which can be placed in hidden form fields to thwart CSRF attacks

    :idle-timeout   - Maximum number of seconds the session can be idle (integer)

    :max-age        - Maximum number of seconds the session exist (integer)

    :last-access    - Date/time of last activity with session, expressed as milliseconds since the Unix epoch

    :created-at     - Date/time of session creation, expressed as milliseconds since the Unix epoch

    See the convenience function `make-auth-session` for making auth sessions.

  For general information about HTTPS routes and development practices, see the README."
  [handler & [options]]
  (let [session-store (or (:store options) (memory/memory-store))]
    (fn [request]
      (let [auth-session-id   (get-in request [:cookies auth-cookie :value])
            auth-session      (and auth-session-id (read-auth-session request session-store auth-session-id))
            request           (if auth-session (assoc request :auth-session auth-session) request)
            response          (handler request)
            new-auth-session  (:auth-session response)]
        (cond
          (and (contains? response :auth-session) (nil? new-auth-session)) ;; delete auth session
            (do
              (store/delete-session session-store auth-session-id)
              (assoc response :cookies
                (merge (:cookies response)
                       {auth-cookie {:value "" :max-age 0}})))

          (and new-auth-session (not (secure? request))) ;; log error and don't set cookie
            (do
              (log/errorf "Refusing to set auth session on insecure request %s" (essential-request request))
              (dissoc response :auth-session))

          (and new-auth-session (secure? request)) ;; set the new auth-session, changing the id
            (let [id (str (UUID/randomUUID))
                  session (merge (make-auth-session (* 30 60) (* 24 60 60))
                                 new-auth-session
                                 {:last-access (coerce/to-long (time/now))})]
              (if auth-session
                (store/delete-session session-store auth-session-id))
              (store/write-session session-store id session)
              (assoc response :cookies
                (merge (:cookies response)
                       {auth-cookie {:value id :max-age (:max-age session) :secure true :http-only true}})))

          (nil? auth-session-id) ;; no auth session, don't do anything
            response

          (nil? auth-session) ;; delete the old cookie
            (assoc response :cookies
              (merge (:cookies response)
                     {auth-cookie {:value "" :max-age 0}}))

          auth-session ;; update the auth session's last-access
            (do
              (if (time/after? (time/now) (time/plus (coerce/from-long (:last-access auth-session)) (time/seconds 30)))
                (store/write-session session-store auth-session-id (assoc auth-session :last-access (coerce/to-long (time/now)))))
              response))))))
