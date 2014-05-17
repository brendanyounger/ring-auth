(ns ring-auth.middleware-test
  (:require
    [clojure.test :refer :all]
    [ring.util.response :as response]
    [ring-auth.middleware :refer :all]
    [ring.middleware.session.store :as store]
    [ring.middleware.session.memory :as memory]))

(def session
  (make-auth-session (* 30 60) (* 24 60 60)))

(def base-request
  { :server-port    443
    :server-name    "localhost"
    :remote-addr    "localhost"
    :uri            "/"
    :query-string   ""
    :scheme         :https
    :request-method :get
    :headers        {}
    :cookies        {"auth-id" {:value "a"}} })

(def session-store (memory/memory-store))

(def ignore-session-route
  (->
    (fn [request]
      (response/response "ok"))
    (wrap-auth-session {:store session-store})))

(def update-session-route
  (->
    (fn [request]
      (->
        (response/response "ok")
        (assoc-in [:auth-session :user-id] "1")))
    (wrap-auth-session {:store session-store})))

(def delete-session-route
  (->
    (fn [request]
      (->
        (response/response "ok")
        (assoc :auth-session nil)))
    (wrap-auth-session {:store session-store})))

(use-fixtures :each
  (fn [next]
    (store/write-session session-store "a" session)
    (next)))

(deftest delete-session
  (testing "Testing deletion of session"
    (let [response (delete-session-route base-request)]
      (is (nil? (:auth-session response)))
      (is (nil? (store/read-session session-store "a"))))))

(deftest insecure-session
  (testing "Testing insecure session"
    (let [request (assoc base-request :scheme :http)
          response (update-session-route request)]
      (is (nil? (:auth-session response))))))

(deftest new-session
  (testing "Testing creation of a new session"
    (let [request (dissoc base-request :cookies)
          response (update-session-route request)
          session-id (get-in response [:cookies "auth-id" :value])]
      (is (not (nil? (store/read-session session-store session-id)))))))

(deftest update-session
  (testing "Testing update of a session"
    (let [response (update-session-route base-request)
          session-id (get-in response [:cookies "auth-id" :value])]
      (is (nil? (store/read-session session-store "a")))
      (is (not (nil? (store/read-session session-store session-id)))))))

(deftest cookie-attrs
  (testing "Testing setting of cookie attributes"
    (let [response (update-session-route base-request)
          cookie (get-in response [:cookies "auth-id"])]
      (is (= true (:http-only cookie)))
      (is (= true (:secure cookie))))))

(deftest timed-out-session
  (testing "Testing timeout of session"
    (store/write-session session-store "a" (make-auth-session 0 0))
    (Thread/sleep (* 2 1000))
    (ignore-session-route base-request)
    (is (nil? (store/read-session session-store "a")))))
