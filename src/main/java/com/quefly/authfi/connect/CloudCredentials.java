package com.quefly.authfi.connect;

import com.google.gson.annotations.SerializedName;

/** Temporary cloud credentials returned by AuthFI Connect. */
public class CloudCredentials {

    private String provider;

    @SerializedName("access_token")
    private String accessToken;

    @SerializedName("access_key_id")
    private String accessKeyId;

    @SerializedName("secret_access_key")
    private String secretAccessKey;

    @SerializedName("session_token")
    private String sessionToken;

    @SerializedName("expires_at")
    private String expiresAt;

    @SerializedName("expires_in")
    private int expiresIn;

    private String region;
    private String account;
    private String role;

    /** Cloud provider (gcp, aws, azure, oci). */
    public String getProvider() { return provider; }

    /** GCP/Azure access token. */
    public String getAccessToken() { return accessToken; }

    /** AWS access key ID. */
    public String getAccessKeyId() { return accessKeyId; }

    /** AWS secret access key. */
    public String getSecretAccessKey() { return secretAccessKey; }

    /** AWS session token. */
    public String getSessionToken() { return sessionToken; }

    /** ISO timestamp when credentials expire. */
    public String getExpiresAt() { return expiresAt; }

    /** Seconds until expiry. */
    public int getExpiresIn() { return expiresIn; }

    /** Cloud region. */
    public String getRegion() { return region; }

    /** Cloud account/project ID. */
    public String getAccount() { return account; }

    /** Role used for this credential. */
    public String getRole() { return role; }
}
