# Stage 13 — Camera Demo Privacy Architecture

The **Live Camera Verification Demo** (`frontend/src/components/CameraDemoPreview.tsx`) is an explicit, optional visual demonstration and **is never equivalent to or used as cryptographic authentication**.

## Strict Privacy Guarantees
1. **Explicit Consent Only:** Camera never starts on page load or login; the user must explicitly open the widget and click **Start Camera Preview** after reading the privacy notice.
2. **Zero Capture / Zero Upload:** No video recording, no automatic snapshots, no frame uploads, and no facial templates are created or stored.
3. **Zero Biometric Storage:** `navigator.mediaDevices.getUserMedia({ video: true, audio: false })` renders directly to a local `<video>` element only.
4. **Immediate Track Teardown:** Clicking **Stop Camera**, closing the dialog, or navigating away immediately stops all `MediaStreamTrack`s (`track.stop()`).
5. **Audit Only Lifecycle:** `/api/v1/identity-assurance/camera-demo/event` records only `STARTED`, `STOPPED`, or `PERMISSION_DENIED` with `assurance_level="DEMO_VISUAL_NON_AUTH"`.
