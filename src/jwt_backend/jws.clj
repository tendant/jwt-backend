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

(defn match-token
  [token-name authorization]
  (if (and token-name
           authorization)
    (-> (re-pattern (str "^" token-name " (.+)$"))
        (re-find authorization)
        second)))

(defn match-tokens
  [token-name tokens authorization]
  (if token-name
    (match-token token-name authorization)
    (some #(match-token % authorization) tokens)))

(defn parse-authorization
  [request token-name tokens]
  (let [auth (or (get-in request [:cookies "Authorization" :value])
                 (get-in request [:headers "authorization"]))]
    (match-tokens token-name tokens auth)))

(defn jws-backend
  [{:keys [secret authfn unauthorized-handler options token-name tokens on-error]
    :or {authfn identity
         token-name "Token"
         tokens []}}]
  {:pre [(ifn? authfn)]}
  (reify
    proto/IAuthentication
    (-parse [_ request]
      (parse-authorization request token-name tokens))

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