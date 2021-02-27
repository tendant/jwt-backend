(ns jwt-backend.jws
  (:require [buddy.auth.protocols :as proto]
            ;; [buddy.auth.http :as http]
            [buddy.auth :as auth]
            [buddy.sign.jwt :as jwt]))

(defn- handle-unauthorized-default
  "A default response constructor for an unauthorized request."
  [request]
  (if (auth/authenticated? request)
    {:status 403 :headers {} :body "Permission denied"}
    {:status 401 :headers {} :body "Unauthorized"}))

(defn- parse-authorization
  [request token-name]
  (some->> (or (get-in request [:cookies "Authorization" :value])
               (get-in request [:headers "authorization"]))
           (re-find (re-pattern (str "^" token-name " (.+)$")))
           (second)))

(defn jws-backend
  [{:keys [secret authfn unauthorized-handler options token-name on-error]
    :or {authfn identity token-name "Token"}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-authorization request token-name))

    (-authenticate [_ request data]
      (try
        (authfn (jwt/unsign data secret options))
        (catch clojure.lang.ExceptionInfo e
          (let [data (ex-data e)]
            (when (fn? on-error)
              (on-error request e))
            nil))))

    proto/IAuthorization
    (-handle-unauthorized [_ request metadata]
      (if unauthorized-handler
        (unauthorized-handler request metadata)
        (handle-unauthorized-default request)))))