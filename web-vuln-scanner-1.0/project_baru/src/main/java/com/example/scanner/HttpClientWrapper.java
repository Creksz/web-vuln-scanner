package com.example.scanner;

import org.apache.http.Header;
import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.cookie.Cookie;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HttpClientWrapper {
    private HttpClientContext context;
    private CookieStore cookieStore;

    public HttpClientWrapper() {
        this.cookieStore = new BasicCookieStore();
        this.context = HttpClientContext.create();
        context.setCookieStore(cookieStore);
    }

    public boolean login(String loginUrl, String username, String password) throws Exception {
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(cookieStore).build()) {
            HttpPost post = new HttpPost(loginUrl);
            List<NameValuePair> params = new ArrayList<>();
            params.add(new BasicNameValuePair("username", username));
            params.add(new BasicNameValuePair("password", password));
            params.add(new BasicNameValuePair("Login", "Login"));
            post.setEntity(new UrlEncodedFormEntity(params));
            try (CloseableHttpResponse response = client.execute(post, context)) {
                String respBody = EntityUtils.toString(response.getEntity());
                return respBody.contains("Welcome") || !respBody.contains("Login failed");  // Cek success
            }
        }
    }

    public String sendGet(String url, Map<String, String> params) throws Exception {
        String fullUrl = url + (params.isEmpty() ? "" : "?" + buildQuery(params));
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(cookieStore).build()) {
            HttpGet request = new HttpGet(fullUrl);
            request.setHeader("User -Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            try (CloseableHttpResponse response = client.execute(request, context)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    public String sendPost(String url, Map<String, String> params) throws Exception {
        try (CloseableHttpClient client = HttpClients.custom().setDefaultCookieStore(cookieStore).build()) {
            HttpPost request = new HttpPost(url);
            List<NameValuePair> nvps = new ArrayList<>();
            for (Map.Entry<String, String> entry : params.entrySet()) {
                nvps.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
            }
            request.setEntity(new UrlEncodedFormEntity(nvps));
            request.setHeader("User -Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            try (CloseableHttpResponse response = client.execute(request, context)) {
                return EntityUtils.toString(response.getEntity());
            }
        }
    }

    public List<Cookie> getCookies() {
        return cookieStore.getCookies();
    }

    private String buildQuery(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (sb.length() > 0) sb.append("&");
            sb.append(entry.getKey()).append("=").append(entry.getValue());
        }
        return sb.toString();
    }
}