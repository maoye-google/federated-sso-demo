# Federated SSO Demo

This project demonstrates a federated Single-Sign-On (SSO) scenario using Keycloak and a Python Flask application, all running in containers.

## Overview

The system is composed of:
- **Three Keycloak Realms**:
    1.  `domain-1-idp`: A local Identity Provider for `domain-1.com` with user `user-1@domain-1.com`.
    2.  `domain-2-idp`: A local Identity Provider for `domain-2.com` with user `user-2@domain-2.com`.
    3.  `federated-idp`: The central federated IDP that trusts the other two realms and provides SSO for the demo application.
- **A Demo Application (`sso-app`)**:
    - A simple Flask web application that relies on the `federated-idp` for user authentication.

## Prerequisites

- `podman`
- `podman-compose` (or `docker-compose`)

## How to Run

1.  **Start the services:**
    Open a terminal in the project root and run:
    ```bash
    podman-compose up --build -d
    ```
    This will build the Flask application image and start both the Keycloak and the application containers in the background.

2.  **Access the Demo Application:**
    Open your web browser and navigate to:
    [http://localhost:5000](http://localhost:5000)

## How to Test the SSO Flow

1.  On the application home page, click **Login**.
2.  You will be redirected to the `federated-idp` login page. This page will show buttons to log in with "Domain 1 IDP" or "Domain 2 IDP".
3.  **Test User 1:**
    - Click on **Domain 1 IDP**.
    - You will be redirected to the `domain-1-idp` login page.
    - Enter the credentials:
        - **Username:** `user-1@domain-1.com`
        - **Password:** `password`
    - After a successful login, you will be redirected back to the demo application's profile page.
    - The page will display your new federated username: **`test-1@sso.com`**.

4.  **Logout** from the application.

5.  **Test User 2:**
    - Click **Login** again.
    - This time, click on **Domain 2 IDP**.
    - You will be redirected to the `domain-2-idp` login page.
    - Enter the credentials:
        - **Username:** `user-2@domain-2.com`
        - **Password:** `password`
    - You will be redirected back to the profile page, which will now show the username: **`test-2@sso.com`**.

## Accessing Keycloak Admin Console

- **URL:** [http://localhost:8080/auth/admin/](http://localhost:8080/auth/admin/)
- **Username:** `admin`
- **Password:** `admin`

From the console, you can explore the three different realms (`domain-1-idp`, `domain-2-idp`, `federated-idp`) to see how the users, clients, and identity brokering are configured.

## Stopping the System

To stop the containers, run:
```bash
podman-compose down
```
