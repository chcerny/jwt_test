package com.cerny.test.jwt;

import java.io.FileInputStream;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import java.util.Base64;

import java.security.interfaces.*;
import java.util.Date;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;

// Generation of the certificate
//
// keytool -genkey -alias jwttest -keystore certificatestore.jks -keypass jwttest -storepass jwttest -dname "cn=JwtTest" -keyalg RSA
// keytool -export -alias jwttest -keystore certificatestore.jks -keypass jwttest -storepass jwttest -file jwttest.cer
// keytool -exportcert -alias jwttest -keystore certificatestore.jks -keypass jwttest -storepass jwttest -rfc -file jwttest.pem
// openssl x509 -inform der -in jwttest.cer -out jwttest.pem

public class JwtTest {
    private static final String USER = "cernytest/test01"; // options: admin, jwttest, cernytest/test01, cernytest/test02
    private static final String ISSUER = "jwttest";
    private static final String AUDIENCE = "https://localhost:9443/oauth2/token";
    private static final String CLIENT_ID = "r9iRKkp6kYkyZW61YB8joQP07LMa";
    private static final String CLIENT_SECRET = "jWrfbPS6ZOhgAwutkSxNLdrUCDEa";
    // private static final String ID_TOKEN = "";
    private static final String ID_TOKEN = "eyJ4NXQiOiJObUptT0dVeE16WmxZak0yWkRSaE5UWmxZVEExWXpkaFpUUmlPV0UwTldJMk0ySm1PVGMxWkEiLCJraWQiOiJkMGVjNTE0YTMyYjZmODhjMGFiZDEyYTI4NDA2OTliZGQzZGViYTlkIiwiYWxnIjoiUlMyNTYifQ.eyJhdF9oYXNoIjoiM3lrTHVFZm1NNnZ1X3l3YXU2cElFQSIsImlzcyI6Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImFwcDAxIjpbInJvbGUtMDEtMDEtMDEiLCJyb2xlLTAxLTAxLTAyIl0sImNvbXBldGVuY3kwMSI6ImNvbXBldGVuY3ktMDEtMDEiLCJnaXZlbl9uYW1lIjoidGVzdDAxIiwiY29tcGV0ZW5jeTAyIjoiY29tcGV0ZW5jeS0wMS0wMiIsImNvbXBldGVuY3kwNSI6ImNvbXBldGVuY3ktMDEtMDUiLCJhY3IiOiJ1cm46bWFjZTppbmNvbW1vbjppYXA6c2lsdmVyIiwiYXVkIjpbInI5aVJLa3A2a1lreVpXNjFZQjhqb1FQMDdMTWEiLCJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMlwvdG9rZW4iXSwiY29tcGV0ZW5jeTAzIjoiY29tcGV0ZW5jeS0wMS0wMyIsImNvbXBldGVuY3kwNCI6ImNvbXBldGVuY3ktMDEtMDQiLCJhenAiOiJyOWlSS2twNmtZa3laVzYxWUI4am9RUDA3TE1hIiwiZXhwIjoxNTI0NDc0NjY4LCJmYW1pbHlfbmFtZSI6InRlc3QwMSIsImlhdCI6MTUyNDQ3MTA2OH0.Dg7vKvC9shCX-tj9K9Iep1re1ctrnUtDgpH6mtuLz1N_kqIH-sdV1drgHOfQwfNRI-9o5N9qZDzSX0C0_DrDlAbkbbhB1g6EsVt2LWDLrVwRpSrQzdmmpTnwW-pKdijKB7R7lZdz19At1MVbSVJAQHxJYqXI4WFsrtdVaFqpArA";

    public static void main(String[] args) throws Exception {
        generateJwt();

        decodeIdToken();
    }

    private static void generateJwt() throws Exception {
        System.out.println("===== generateJwt() - START =====");

        FileInputStream is = new FileInputStream("./src/main/resources/certificatestore.jks");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "jwttest".toCharArray());

        String alias = "jwttest";

        Key key = keystore.getKey(alias, "jwttest".toCharArray());
        Certificate cert = keystore.getCertificate(alias);

        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = (PrivateKey) key;

        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        System.out.println("Public Key: " + publicKeyString);
        System.out.println("Private Key: " + privateKeyString);

        // RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

        // Create RSA-signer with the private key
        JWSSigner signer = new RSASSASigner(rsaPrivateKey);

        // Prepare JWT with claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(USER)
                .issuer(ISSUER)
                .audience(AUDIENCE)
                .expirationTime(new Date(new Date().getTime() + 60 * 60 * 1000))
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);

        // Compute the RSA signature
        signedJWT.sign(signer);

        String signedJWTString = signedJWT.serialize();

        System.out.println("Signed JWT: " + signedJWTString);
        System.out.println();
        System.out.println("curl -i -X POST -u " + CLIENT_ID + ":" + CLIENT_SECRET + " -k -d 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + signedJWTString + "' -H 'Content-Type: application/x-www-form-urlencoded' https://localhost:9443/oauth2/token?scope=openid");
        System.out.println("curl -k -H 'Authorization: Bearer <ACCESS_TOKEN>' https://localhost:9443/oauth2/userinfo?scope=openid");

        System.out.println("===== JwtTest - END =====");
    }

    private static void decodeIdToken() throws Exception {
        System.out.println("===== generateJwt() - START =====");

        FileInputStream is = new FileInputStream("/Users/chcerny/prod/wso2/wso2is-5.3.0_wip/repository/resources/security/wso2carbon.jks");

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "wso2carbon".toCharArray());

        String alias = "wso2carbon";

        Key key = keystore.getKey(alias, "wso2carbon".toCharArray());
        Certificate cert = keystore.getCertificate(alias);

        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = (PrivateKey) key;

        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String privateKeyString = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        System.out.println("Public Key: " + publicKeyString);
        System.out.println("Private Key: " + privateKeyString);

        RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;

        SignedJWT signedJWT = SignedJWT.parse(ID_TOKEN);

        JWSVerifier verifier = new RSASSAVerifier(rsaPublicKey);

        System.out.println();

        if (signedJWT.verify(verifier)) {
            System.out.println("Signature is Valid");
        } else {
            System.out.println("Signature is NOT Valid");
        }

        System.out.println("signedJWT: " + signedJWT.getJWTClaimsSet().toString());

        System.out.println("===== JwtTest - END =====");
    }
}