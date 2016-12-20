/*
 * Copyright 2016 Kantega AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package org.kantega.respiro.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import org.bouncycastle.util.encoders.Base64;
import org.kantega.reststop.api.Config;
import org.kantega.reststop.api.Export;
import org.kantega.reststop.api.Plugin;
import org.kantega.reststop.api.ServletBuilder;
import org.slf4j.Logger;

import javax.servlet.Filter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;

import static org.kantega.reststop.api.FilterPhase.AUTHENTICATION;
import static org.slf4j.LoggerFactory.getLogger;

/**
 */
@Plugin
public class JWTVerifyerPlugin {

    private static final Logger logger = getLogger(JWTAuthenticationFilter.class);

    @Export
    private final Filter authenticationFilter;

    public JWTVerifyerPlugin(@Config String jwtLoginUrl,
                             @Config String jwtIssuerPublicKeyFile,
                             @Config String jwtServerPrivateKeyFile,
                             @Config String jwtIssuerAlias,
                             @Config(defaultValue = "respiro-auth-token") String jwtCookieName,
                             @Config(doc = "ALL or comma delimited list of audiences.") String jwtAllowedAudiences,
                             ServletBuilder servletBuilder) {

        // load keys:
        try {
            final JWTAuthenticationFilter.JWTConfig config = new JWTAuthenticationFilter.JWTConfig(
                    jwtLoginUrl, jwtCookieName
            );

            final KeyFactory kf = KeyFactory.getInstance("RSA");
            /*final RSAPrivateKey serverKey = (RSAPrivateKey) loadKeyFromKeystore(Paths.get(jwtIssuerPublicKeyFile),
                    kf::generatePrivate, PKCS8EncodedKeySpec::new);*/
            final RSAPublicKey issuerKey = (RSAPublicKey) loadKeyFromKeystore(Paths.get(jwtIssuerPublicKeyFile),
                    kf::generatePublic, X509EncodedKeySpec::new);
            // setup JWT Verifyer
            JWTVerifier.Verification verification = JWT.require(Algorithm.RSA256(issuerKey))
                            .withIssuer(jwtIssuerAlias);
            if (!"all".equals(jwtAllowedAudiences.toLowerCase()))
                verification = verification.withAudience(jwtAllowedAudiences.split(","));
            final JWTVerifier verifier = verification.build();

            authenticationFilter = servletBuilder.filter(new JWTAuthenticationFilter(verifier, config), "/*", AUTHENTICATION);

        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to initialize JWS Plugin", e);
            throw new RuntimeException(e);
        }

    }

    private static <T extends EncodedKeySpec> Key loadKeyFromKeystore(Path keyFile, KeyGenerator generator, Spec<T> specCreator) {

        try {
            byte[] keyBytes = Files.readAllBytes(keyFile);

            keyBytes = Base64.decode(keyBytes);

            T spec = specCreator.create(keyBytes);

            return generator.generate(spec);
        } catch (InvalidKeySpecException | IOException e) {
            logger.error("Failed to read JWT public key from " + keyFile, e);
            throw new RuntimeException(e);
        }
    }

    private interface KeyGenerator {
        Key generate(KeySpec spec) throws InvalidKeySpecException;
    }

    private interface Spec<T> {
        T create(byte[] key);
    }
}
