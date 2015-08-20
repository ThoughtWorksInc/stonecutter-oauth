(ns stonecutter-oauth.test.jwt
 (:require [midje.sweet :refer :all]
           [stonecutter-oauth.jwt :as jwt]))

(def token-expiring-in-500-years "eyJraWQiOiJ0ZXN0LWtleSIsImFsZyI6IlJTMjU2In0.eyJpc3MiOiJJU1NVRVIiLCJhdWQiOiJDTElFTlRfSUQiLCJleHAiOjE3MjA3OTkzMjUyLCJpYXQiOjE0Mzk5OTI3NDAsInN1YiI6IlNVQkpFQ1QiLCJyb2xlIjoiYWRtaW4iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZW1haWwiOiJlbWFpbEBhZGRyZXNzLmNvbSJ9.PQWWJQGECzC8EchkfwGjQBBUfhFGoLDOjZ1Ohl1t-eo8rXDO4FxONk3rYEY9v01fVg3pzQW8zLJYcZ73gyE2ju8feHhwS8wYwcsgKq6XC-Zr9LwRJIeFpZoVcgMpvW21UHX1bxAhHE7WM_UzSerKtGkIuK21XraGVTiIB-0o8eWOJX0Rud8FXC3Cr0LdZeqDytPZDwM1Pbcr0eFyfNq9ngi75BFNTGHCMLGshJGt1LvQhDtTWifXDlwW5uk-kuOVavnQGK_i7qvrcy8c7lFCCPqd5X3x6EZJyfk-BZGgDT1ySwdM2EjRAi1W1nPAmdWms9rts0rkbk_Q73gEkWQpOw")

(def token-content {:aud "CLIENT_ID"
                    :email "email@address.com"
                    :email_verified true
                    :exp 17207993252
                    :iat 1439992740
                    :iss "ISSUER"
                    :role "admin"
                    :sub "SUBJECT"})

(facts "about decoding openid connect id tokens"
       (fact "can decode a signed id token"
             (let [public-key (jwt/load-json-web-key "./test/stonecutter_oauth/test-key.json")]
               (jwt/decode public-key "CLIENT_ID" "ISSUER" token-expiring-in-500-years) => token-content)))
