# ring-auth

Ring middleware that manages authenticated Ring sessions.

## Rationale

Keeping authentication tokens secure is a tricky job.  There are several different attacks which can reveal an authentication token and it's hard to architect a webapp to be immune to all of them.  `ring-auth` aims to implement all of [OWASP's recommendations](https://www.owasp.org/index.php/Session_Management_Cheat_Sheet) when it comes to authenticated session storage.

## Usage

The function `wrap-auth-session` provides a `:auth-session` key in the Ring request map which behaves exactly like Ring's session middleware except that the session can be relied upon to maintain a secure authentication token with your users.

The basic usage is as follows

````clojure
(def app-routes
  (->
    ...
    (wrap-auth-session session-store)
    (wrap-session {:store session-store})))
````

Note that `wrap-auth-session` requires the cookie middleware so should come before either `wrap-session` or `wrap-cookies`.

Starting a new authentication session is as simple as

````clojure
(assoc response :auth-session
  (assoc
    (make-auth-session (* 30 60) (* 24 60 60))
    :user-id "ABCDEF"))
````

and to log out/destroy the session, simply set the `:auth-session` key `nil`.

## Developing with HTTPS

Since this middleware relies on HTTPS browser features, you will need to develop with HTTPS routes when using `:auth-session`.

The easiest way begin is to create a keystore via

````sh
keytool -keystore keystore -alias jetty -genkey -keyalg RSA
````

and launch your local Jetty instance with

````clojure
(run-jetty
  app-routes
  { :port 8080
    :ssl-port 8443
    :join? false
    :ssl? true
    :keystore "keystore"
    :key-password "your passphrase here" })
````

You can now use HTTPS routes locally and test with `auth-session` appropriately.

## Suggestions

In general, you should only store user authentication credentials in the auth session.  Permanent user settings and the like should probably be changed in a User datastore.  However, anything stored in the normal Ring `:session` map can be tampered with by third parties, so never store sensitive user information in that session.  In particular, never trust data in the `:session` map when making authorization decisions.

If any clear breach of security (sending the cookie over HTTP, etc.) occurs, an error will be logged and appropriate action to destroy the session will be taken.  Keep an eye on your logs while developing.

## Planned features

* Tie the auth-session to the user's IP address
* Set the header Cache-Control: no-cache="Set-Cookie, Set-Cookie2"
* Tie the authenticated session to the unauthenticated session (if present)

## Contact

Please feel free to suggest improvements or changes to this library.  The intent is for this library to meet everyone's secure session needs.

## License

Copyright © 2014 Brendan Younger.

Distributed under the Eclipse Public License either version 1.0 or (at
your option) any later version.
