# PROJECT_PAREWA_AUDIT.md

## Project Parewa: Self-Hosted Architecture & Gap Analysis

**Date:** 2026-07-25
**Scope:** Android Client & Node.js Backend

Project Parewa is a self-hosted, end-to-end encrypted messaging platform based on Signal-Android. To decouple the client from Signal's production infrastructure and minimize maintenance overhead for a 10-15 user deployment, we must systematically audit and bypass features that rely on cloud-specific enclaves, external CDNs, or monetization infrastructure, while retaining the core Signal Protocol cryptography and WebRTC capabilities.

### 1. Features to Strip / Bypass (Unneeded Cloud Dependencies)

*   **Key Management Service (KMS / SVR / KBS):**
    *   *Purpose:* Signal uses Intel SGX enclaves to securely backup user PINs and restore data.
    *   *Action:* Completely bypass PIN creation. Force the client state to `opted-out` of KBS. We will rely on local device storage and manual backups, eliminating the need for a complex SGX enclave backend.
*   **Contact Discovery Service (CDS / SGX):**
    *   *Purpose:* Signal hashes address books and uploads them to an SGX enclave to find matches without revealing the user's contacts to the server.
    *   *Action:* Since Parewa is a private network for 10-15 users, privacy from the server is trusted. We will replace this with simple, direct PostgreSQL/Redis directory lookups (returning mock matches for now).
*   **Payments / MobileCoin:**
    *   *Purpose:* In-app cryptocurrency integration.
    *   *Action:* Disable UI entry points and strip payment-related network requests.
*   **Signal Stories & Stickers:**
    *   *Purpose:* Heavy media features relying on `cdn.signal.org`.
    *   *Action:* We are seeing 404s for sticker manifests in our Nginx logs. We will either mock a basic manifest returning an empty list or disable sticker fetching entirely in the client.
*   **Twilio / SMS Fallbacks:**
    *   *Purpose:* Legacy phone number verification.
    *   *Action:* Successfully bypassed and replaced with our custom Email OTP service (`/v1/accounts/code`).

### 2. Core Functionality to Retain & Implement (Self-Hosted MVP)

*   **E2EE Key Management:**
    *   *Requirement:* The core of the Signal Protocol.
    *   *Action:* Implement `PUT /v2/keys` to accept and store ACI/PNI PreKeys (Signed PreKeys, One-Time PreKeys, Kyber Keys). Implement `GET /v2/keys/:identifier` for key fetching during session establishment.
*   **Real-time Messaging (WebSockets):**
    *   *Requirement:* Delivery of ephemeral messages.
    *   *Action:* Implement a WebSocket server on the Node.js backend (`/v1/websocket`) to push incoming messages and handle delivery receipts.
*   **Media / Attachments:**
    *   *Requirement:* Sending images/videos securely.
    *   *Action:* Implement basic S3-compatible or local disk storage endpoints (`/v1/attachments`) to handle encrypted binary blobs.
*   **Local Directory Search:**
    *   *Requirement:* Finding other users on the self-hosted network.
    *   *Action:* Implement basic mocking for `/v1/directory/tokens` and profile fetching `/v1/profiles/:identifier`.
*   **WebRTC Calling (SCS):**
    *   *Requirement:* Audio/Video calls.
    *   *Action:* Utilize our existing `coturn` server. Provide TURN credentials via the backend configuration endpoints.

---

*This document serves as the architectural roadmap for Project Parewa's MVP.*
