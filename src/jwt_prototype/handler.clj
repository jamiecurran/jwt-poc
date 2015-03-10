(ns jwt-prototype.handler
  (:require [compojure.core :refer :all]
            [compojure.route :as route]
            [ring.middleware.defaults :refer [wrap-defaults api-defaults]]
            [clj-jwt.core  :refer :all]
            [clj-time.core :refer [now plus days]]
            [ring.middleware.json :refer [wrap-json-params]]
            [clojure.string :as str]))

(def claim
  {:iss "shipa"
   :exp (plus (now) (days 1))
   :iat (now)})


(defn user-id [token]
  (let [decoded-jwt (str->jwt token)]
    (get-in decoded-jwt [:claims :id])))

(defn generate-jwt [{password "password" id "id"}]
  (-> (assoc claim :id id)
      jwt
      (sign :HS256 "secret")
      to-str))

(defn verify-jwt [token]
  (-> token
      str->jwt
      (verify "secret")))

(defn get-token [authorization-header]
  (let [[_ token] (str/split authorization-header #" ")]
    token))

(defn authorised? [{authorization "authorization"}]
    (-> authorization
        get-token
        verify-jwt))

;(defn wrap-security-jwt [handler]
;  (fn [request]
;    (when-let [authorization-header (get-in request [:headers :authorization])]
;      (when (authorised? authorization-header)
;    (update-in request [:headers] merge {:X-USER (user-id (get-token (get-in request [:headers :authorization])))})
;    (handler request)))

(defn wrap-security-jwt [handler]
  (fn [request]
    (when (authorised? (:headers request))
      (update-in request [:headers] merge {"X-USER" "jamie"}))))

(defroutes app-routes
  (POST "/session" request (generate-jwt (:params request)))
  (GET "/authenticated" request (if (authorised? (:headers request)) {:status 200} {:status 422}))
  (route/not-found "Not Found"))

(def app
  (-> app-routes
      wrap-json-params
      wrap-security-jwt
      (wrap-defaults api-defaults)))