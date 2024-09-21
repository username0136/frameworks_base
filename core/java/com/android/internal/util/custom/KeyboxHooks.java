/*
 * Copyright (C) 2024 crDroid Android Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.internal.util.custom;

import android.os.SystemProperties;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyEntryResponse;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * @hide
 */
public final class KeyboxHooks {

    private static final String TAG = KeyboxHooks.class.getSimpleName();
    private static final boolean DEBUG = false;

    private static final PrivateKey EC, RSA;
    private static final byte[] EC_CERTS;
    private static final byte[] RSA_CERTS;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static final CertificateFactory certificateFactory;
    private static final X509CertificateHolder EC_holder, RSA_holder;
    private static volatile String algo;

    static {
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");

            EC = parsePrivateKey(Keybox.EC.PRIVATE_KEY, KeyProperties.KEY_ALGORITHM_EC);
            RSA = parsePrivateKey(Keybox.RSA.PRIVATE_KEY, KeyProperties.KEY_ALGORITHM_RSA);

            byte[] EC_cert1 = parseCert(Keybox.EC.CERTIFICATE_1);
            byte[] RSA_cert1 = parseCert(Keybox.RSA.CERTIFICATE_1);

            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            stream.write(EC_cert1);
            stream.write(parseCert(Keybox.EC.CERTIFICATE_2));
            stream.write(parseCert(Keybox.EC.CERTIFICATE_3));

            EC_CERTS = stream.toByteArray();

            stream.reset();

            stream.write(RSA_cert1);
            stream.write(parseCert(Keybox.RSA.CERTIFICATE_2));
            stream.write(parseCert(Keybox.RSA.CERTIFICATE_3));

            RSA_CERTS = stream.toByteArray();

            stream.close();

            EC_holder = new X509CertificateHolder(EC_cert1);
            RSA_holder = new X509CertificateHolder(RSA_cert1);

        } catch (Throwable t) {
            if (DEBUG) Log.e(TAG, Log.getStackTraceString(t));
            throw new RuntimeException(t);
        }
    }

    private static PrivateKey parsePrivateKey(String str, String algo) throws Throwable {
        byte[] bytes = Base64.getDecoder().decode(str);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance(algo).generatePrivate(spec);
    }

    private static byte[] parseCert(String str) {
        return Base64.getDecoder().decode(str);
    }

    private static byte[] getCertificateChain(String algo) throws Throwable {
        if (KeyProperties.KEY_ALGORITHM_EC.equals(algo)) {
            return EC_CERTS;
        } else if (KeyProperties.KEY_ALGORITHM_RSA.equals(algo)) {
            return RSA_CERTS;
        }
        throw new Exception();
    }

    private static byte[] modifyLeaf(byte[] bytes) throws Throwable {
        X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));

        if (leaf.getExtensionValue(OID.getId()) == null) throw new Exception();

        X509CertificateHolder holder = new X509CertificateHolder(leaf.getEncoded());

        Extension ext = holder.getExtension(OID);

        ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

        ASN1Encodable[] encodables = sequence.toArray();

        ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

        ASN1EncodableVector vector = new ASN1EncodableVector();

        ASN1Sequence rootOfTrust = null;
        for (ASN1Encodable asn1Encodable : teeEnforced) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
            if (taggedObject.getTagNo() == 704) {
                rootOfTrust = (ASN1Sequence) taggedObject.getObject();
                continue;
            }
            vector.add(asn1Encodable);
        }

        if (rootOfTrust == null) throw new Exception();

        algo = leaf.getPublicKey().getAlgorithm();

        boolean isEC = KeyProperties.KEY_ALGORITHM_EC.equals(algo);

        X509CertificateHolder cert1 = isEC ? EC_holder : RSA_holder;
        PrivateKey privateKey = isEC ? EC : RSA;

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(cert1.getSubject(),
            holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(),
            holder.getSubject(), holder.getSubjectPublicKeyInfo());
        ContentSigner signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(privateKey);

        byte[] verifiedBootKey = new byte[32];
        ThreadLocalRandom.current().nextBytes(verifiedBootKey);

        DEROctetString verifiedBootHash = (DEROctetString) rootOfTrust.getObjectAt(3);

        if (verifiedBootHash == null) {
            byte[] temp = new byte[32];
            ThreadLocalRandom.current().nextBytes(temp);
            verifiedBootHash = new DEROctetString(temp);
        }

        ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey),
            ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

        ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

        ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

        vector.add(rootOfTrustTagObj);

        ASN1Sequence hackEnforced = new DERSequence(vector);

        encodables[7] = hackEnforced;

        ASN1Sequence hackedSeq = new DERSequence(encodables);

        ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

        Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

        builder.addExtension(hackedExt);

        for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
            if (OID.getId().equals(extensionOID.getId())) continue;
            builder.addExtension(holder.getExtension(extensionOID));
        }

        return builder.build(signer).getEncoded();
    }

    public static KeyEntryResponse onGetKeyEntry(KeyEntryResponse response) {
        if (response == null)
            return null;

        if (response.metadata == null)
            return response;

        algo = null;

        try {
            byte[] newLeaf = modifyLeaf(response.metadata.certificate);
            response.metadata.certificateChain = getCertificateChain(algo);

            response.metadata.certificate = newLeaf;

        } catch (Throwable t) {
            if (DEBUG) Log.e(TAG, "onGetKeyEntry", t);
        }

        return response;
    }

    private static final class Keybox {
        public static final class EC {
            public static final String PRIVATE_KEY = "MHcCAQEEICPdEVCfZG4hLD4gI7+Z40UTPnX36fbyo3ZgEvKL+EfuoAoGCCqGSM49AwEHoUQDQgAE7Auh30VZFoMJw9z+9KXmOtq/U+elcG+B3dvTc3qqTd190G5FgtKm6c1lBVAFknV4aKmuWBXILwrl0NHoxZClcA==";
            public static final String CERTIFICATE_1 = "MIICJDCCAaugAwIBAgIKBYcWRnU1coAEFDAKBggqhkjOPQQDAjApMRkwFwYDVQQFExBlMThjNGYyY2E2OTk3MzlhMQwwCgYDVQQMDANURUUwHhcNMTgwNzIzMjAxNzQ3WhcNMjgwNzIwMjAxNzQ3WjApMRkwFwYDVQQFExBlMjNhNWNkYjZlMmZmMmU5MQwwCgYDVQQMDANURUUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATsC6HfRVkWgwnD3P70peY62r9T56Vwb4Hd29NzeqpN3X3QbkWC0qbpzWUFUAWSdXhoqa5YFcgvCuXQ0ejFkKVwo4G6MIG3MB0GA1UdDgQWBBS+1YHUS6wN8nCe7rzSg/XBvUuAPzAfBgNVHSMEGDAWgBStaJfkd3MUTYzmNFYScunw3VEFvjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBUBgNVHR8ETTBLMEmgR6BFhkNodHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsLzA1ODcxNjQ2NzUzNTcyODAwNDE0MAoGCCqGSM49BAMCA2cAMGQCMGnNe3YBEPKG+geXViM1w3KGdcxVs4E9/peHNRaICZnZ1Dyr7vAVdzehxkFyTnPmjAIwQF+1JfaDSvvDWgRYwo19E5qcmlsn34gVy7u7EJqMjKeG+Hp0Yoq4lB9ULqfFlwqA";
            public static final String CERTIFICATE_2 = "MIID0TCCAbmgAwIBAgIKA4gmZ2BliZaFnjANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDcyMzIwMTM0MloXDTI4MDcyMDIwMTM0MlowKTEZMBcGA1UEBRMQZTE4YzRmMmNhNjk5NzM5YTEMMAoGA1UEDAwDVEVFMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEbRn8j/RF9mvI3WO2fMpitlBrovJ+SrHx4KBjW+Bcg1hnYTATavDaNk2O5ADA2KllkHLDSxIUTMMz6Zb7gJUd+/dC3sI701cRh0aWV9RzqnlgdR3IChRY4yuG9BSwoTfmo4G2MIGzMB0GA1UdDgQWBBStaJfkd3MUTYzmNFYScunw3VEFvjAfBgNVHSMEGDAWgBQ2YeEAfIgFCVGLRGxH/xpMyepPEjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDBQBgNVHR8ESTBHMEWgQ6BBhj9odHRwczovL2FuZHJvaWQuZ29vZ2xlYXBpcy5jb20vYXR0ZXN0YXRpb24vY3JsL0U4RkExOTYzMTREMkZBMTgwDQYJKoZIhvcNAQELBQADggIBAEWkf0CP/lLv+RehkJGy3VwI85YJ4ZshZVhUfUD0CcQR9VfGFjEEFN0ako0O+b7noTzZ+fwJqfMClmUkZAnhJtYGJgGnF9bmTq5Itr/Cny0hmCkDdrqO52vi4ILz4gEkUVjLBY1A/UVipmVtkXgvEgdBUBmjv9fD7VP64vandbCAMtZpTCvu8cEAPgyh7EcaVhv1OEy7jahqJOItpoBvFySwQ0+1zF+7xJzLSQZESGb/eU3NimwLhNN/MFbZCQh3itdYZ0wqD6O3uCV/Jlx7SEakp+QOMk98IYA8276DJIgKkko3bLSmWrAP13zkea8geWCTFOfYfBo8g1inmipKNQL/nXTfixdA4OUYzQ/YKfrc5r+ux0EpxYiVEi53/aVMNeSbV+lOzbRctq1VwJPq4a00HBx1jwtZNmSjPWJjFkNu4bEU9bctCSHLsMsjEO3KGJRTGRATK7Dz43QurhwypvN/ZZl1K4NV+9RY4zNZV6ix9mWl+4cQAiPrJtrvohLtz7FM0LYZ3nz+Ak2jiCNQsKpOH3fuALhkQ6xZXVKoXmckEmXUc0wSSJ0qfkPD7SVpxjGeeiFmlWXM6ee1QFwKMcfaWQvqNTbKEihVSqV2BjXvxICsW93WEyqzt/COpcugGlvObeUTrqXuh59lo9ZGllgJgFJeGqByZDbQGawyB4Rc";
            public static final String CERTIFICATE_3 = "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk";
        }
        public static final class RSA {
            public static final String PRIVATE_KEY = "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";
            public static final String CERTIFICATE_1 = "MIIFETCCAvmgAwIBAgIKAVhTVJRFMIkmRTANBgkqhkiG9w0BAQsFADApMRkwFwYDVQQFExBlMThjNGYyY2E2OTk3MzlhMQwwCgYDVQQMDANURUUwHhcNMTgwNzIzMjAxNzM1WhcNMjgwNzIwMjAxNzM1WjApMRkwFwYDVQQFExBlMjNhNWNkYjZlMmZmMmU5MQwwCgYDVQQMDANURUUwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDDXTVtQtUuf0aZr0EP7rXp8YX60feAKDWN0a82sX6ZMbq73akri2hyOlQ5DwO4F2xAQ2RR5IrWtzAGrLNgh4tmlQAdeqfCxlCY+a8LQh6nSTSr41QTx8opWPU77SV7Kh1sZJlYHfzHHimvLY/OhNDOoS7DrvrO+0lrq+kZI+i6kwl/IzsgsZjI/YipaqS3cYSihkQApmgrx5DIT9lUk4U1NrB2jD8zV66eNjMl7IaJFU44fhg/hIARP+fw/Kd9ilNry3UyFOGAcFJP+oeN48sPyqjHGCpKSOU0gjyb0DZ4uli2S7NqRkst9d91nZ7YIjFQkAnDMGCzxac2PBVEUcrAp4y9f+4FjOW3tgnvbUoS+mlVQXvVEAFLjEgVn85cAvDengfJoaqwfccWEttSnNr+YVWV4NsYX663/wJ/kFeXRzYwSsbl7F7Inh3ZVTelo5OwrhEkA+H9ODYbfQzNDg5vpJLommYD6qb/TNi/n8rwQnhsSVbnOnoJNCsjcKci2X8CAwEAAaOBujCBtzAdBgNVHQ4EFgQUuoU9FcKq9bSehpUT2+78aKFkzEswHwYDVR0jBBgwFoAUXu6g9FzerKg37LaULPfvE04Typ4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwVAYDVR0fBE0wSzBJoEegRYZDaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wMTU4NTM1NDk0NDUzMDg5MjY0NTANBgkqhkiG9w0BAQsFAAOCAgEAERpUCubcUHhDLk5zOs/xnPEdvjXTZCE7CQO1dQqhbqcaCLVYRx4D7/JEzh1qQaN+YzvVukBG7IgmNtmgG2cdsJIUCwix7eoFee9p8m9+ChSktjimJ3N0bQEJmGzLnTHhBMts+LpSJUOhBG1jsI4u9To71fzVpRZGcHMcFB1hKXwdNW8dE2Bg5Tg+Kt3NQXrq4QijdqXJ52fOrTAyucgNVje0+ihB0tZcGj6CwqpDjIUsO2Z5hjHti7+TmHR5eEW4BDEFOmM9n95Htl+k2LqQ0q6AmBTj1gb8H5E+q8jYDGX+KwPV6fhuXh543Za3IsWkUYFeLI5sboeIAuovr0xuZCD+M9dMAbmeacreHe9dJHvwCTZApZrTGvrj+YvSByLzfOeX+L7PsDS9Umu757WRZj1WtabXiB1682ip4Zly/Ho3tD1uXT/0Ns2+6BYhOAe6kBQcbS4YXRyBMzBbGyVIUwv68CDH0IhU/JgdzAlzNRMAYBk74uoAIokbaC5updUZM3hx3PR+BYV1mdAD9vmTJmdH5+32+m1gmez4CtrTnAMoYgpzHTtmGbSX5M7yHuxe8gDAEvmE6Bft0GLtB6ur/P/mkr87JXnJ4Vh1VnAGLT9BKNltYuQ9XX4vHYLISjdASmNpNEY+hoY/O8NvzQn+t0ZPF3lL1ABsYGDSAldOiPM=";
            public static final String CERTIFICATE_2 = "MIIFfzCCA2egAwIBAgIKA4gmZ2BliZaFnTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MB4XDTE4MDcyMzIwMTMyNFoXDTI4MDcyMDIwMTMyNFowKTEZMBcGA1UEBRMQZTE4YzRmMmNhNjk5NzM5YTEMMAoGA1UEDAwDVEVFMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1yZeC+RQEXv6YDopNfpKldWHv6vnG0V4WsLOrXILFEGYrWWvF/gZJl0z6X37BONEWUPXZKpVerl6UPBCK7ngjm3XWSrYYTFVceZoJMeVamYguPx2D7Gmj+qrY6Ei4Q32UptczfIRKG6cwb0OpSg1uOhUP3DS4sPRxxbMbQwzJTLgWy4+i9ZPOSLo3HubzghJPmC4ruanFRGhlH8BBJSHtEJhoriWw32x/McfMjD/CzQq/TGFYg2WpKQGyLFgYkkfFnWG83X9h13m9CIH8VpFt4lkM6Ko8ooNDeQr/uuB4H9tlh2Vz0S7Ec3xgisn8VGtWcXzAEAO69IvTzICdxDDXTRzmHij1pfdzUjEK82aZMk81q9FGkq/2rXypOQJqhLpJFC5yMUehXlkn9Xa2JYo27vlBt/TbxUhg6ivRmCWrXOxU5mepNJMVOdRznziO7SqHnbYS9oktTJ5shoPGWdIVNZ3Qzw/mS7wYyljgUWbh1m2EGKvh2VCUaonQu6y6ja730dElHpnZKafGcnyLT2+L4nQS+RK2a1WZqnAROmWXbyj/N8+roIYKhJEq5ofNQmyMPOckEmf/7ritM6384sr67FKTZMKm8iToV5N9/zENtJn3f21LxfX4i3u6VjOQu7qqtPCbgC5KE2GLbF5lelNML2fN8UZCycX2GA1IhcFNk0CAwEAAaOBtjCBszAdBgNVHQ4EFgQUXu6g9FzerKg37LaULPfvE04Typ4wHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC9FOEZBMTk2MzE0RDJGQTE4MA0GCSqGSIb3DQEBCwUAA4ICAQCrUyGwn5prRwZMdQd3v1wuvMrqbkPKo0qUcj12rqTgJg+YbAtk7tapzxLneaFIBTv6S1a9S6vKxXbf/V6mIkFjS0jXpvyFcGSZdfvwUTJY8+C2+MIwg/T/4XWd9aSalJrCLlyh2ACd7EOtUninRLwtfFEDCHI2R4KvTPhFNQBA9RkaI9m9ZH8cEJfBOsxnLtWzsqQBduuezECoGwFVHrkdvpSB9Jbl2WTWR0yZjkCv+j+9gYDc/kYcnyRzdEfMQRK0fNAK0vC2jw5hCdwV4xeg6321whxUTITjHUwyQrZBf3ei6XUXsYsf3Y6+1zeb16YsjoV1mO2G/fFMmKm+jSAU9Zg+rWaKm5GqUTCZkhG7dJZkbPicGljYWkgDl48i7GoCqiN15G2ZUHnvgAtU13fZBQ0ygZYlmmt51IBDaJ0g0TrUQTUy2+XAUFKXz8vg72dMdP+tyjk+An1bylmcnn7EczHgrcvdWgRnD6sH3esVjc1nzkyttIMmTzrrDtESe/Hwc6xVdfM/Tpko3WinZkChsUsyF6U2D5Gdf1/QTbXPeUlKHE2DKVGDlzA8OH5eqOAjVrf0uIMSWbEDSKEsos0x7vA2Nys9jjZZp2o5qPe+8aOKeof48VcctFdAg/M+105LEaX/heJPnqr5tpkZUKSwax4tj82u5NSwUk64cNdrmw==";
            public static final String CERTIFICATE_3 = "MIIFYDCCA0igAwIBAgIJAOj6GWMU0voYMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNVBAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMTYwNTI2MTYyODUyWhcNMjYwNTI0MTYyODUyWjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdSSxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggjnar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGqC4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQoVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+OJtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/EgsTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRiigHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+MRPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9EaDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5UmAGMCAwEAAaOBpjCBozAdBgNVHQ4EFgQUNmHhAHyIBQlRi0RsR/8aTMnqTxIwHwYDVR0jBBgwFoAUNmHhAHyIBQlRi0RsR/8aTMnqTxIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwQAYDVR0fBDkwNzA1oDOgMYYvaHR0cHM6Ly9hbmRyb2lkLmdvb2dsZWFwaXMuY29tL2F0dGVzdGF0aW9uL2NybC8wDQYJKoZIhvcNAQELBQADggIBACDIw41L3KlXG0aMiS//cqrG+EShHUGo8HNsw30W1kJtjn6UBwRM6jnmiwfBPb8VA91chb2vssAtX2zbTvqBJ9+LBPGCdw/E53Rbf86qhxKaiAHOjpvAy5Y3m00mqC0w/Zwvju1twb4vhLaJ5NkUJYsUS7rmJKHHBnETLi8GFqiEsqTWpG/6ibYCv7rYDBJDcR9W62BW9jfIoBQcxUCUJouMPH25lLNcDc1ssqvC2v7iUgI9LeoM1sNovqPmQUiG9rHli1vXxzCyaMTjwftkJLkf6724DFhuKug2jITV0QkXvaJWF4nUaHOTNA4uJU9WDvZLI1j83A+/xnAJUucIv/zGJ1AMH2boHqF8CY16LpsYgBt6tKxxWH00XcyDCdW2KlBCeqbQPcsFmWyWugxdcekhYsAWyoSf818NUsZdBWBaR/OukXrNLfkQ79IyZohZbvabO/X+MVT3rriAoKc8oE2Uws6DF+60PV7/WIPjNvXySdqspImSN78mflxDqwLqRBYkA3I75qppLGG9rp7UCdRjxMl8ZDBld+7yvHVgt1cVzJx9xnyGCC23UaicMDSXYrB4I4WHXPGjxhZuCuPBLTdOLU8YRvMYdEvYebWHMpvwGCF6bAx3JBpIeOQ1wDB5y0USicV3YgYGmi+NZfhA4URSh77Yd6uuJOJENRaNVTzk";
        }
    }
}
