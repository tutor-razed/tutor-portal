export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const student = (url.searchParams.get("student") || "general")
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-");

  const wantsTeacher = url.searchParams.get("teacher") === "1";
  const pin = url.searchParams.get("pin") || "";

  const env = context.env;
  const isTeacher = wantsTeacher && pin === env.TEACHER_PIN;

  const appId = env.JAAS_APP_ID;
  const kid = env.JAAS_KID;
  const privateKeyPem = env.JAAS_PRIVATE_KEY;

  const room = `student-${student}`;

  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: "jitsi",
    iss: "chat",
    sub: appId,
    room: room,
    exp: now + 60 * 60 * 3,
    nbf: now - 10,
    context: {
      user: {
        id: isTeacher ? "teacher" : `student-${student}`,
        name: isTeacher ? "Tutor" : student,
        email: "",
        moderator: isTeacher
      },
      features: {
        livestreaming: false,
        recording: false,
        transcription: false,
        "outbound-call": false
      }
    }
  };

  const jwt = await signJwtRS256(payload, kid, privateKeyPem);

  return Response.json({ jwt, appId, room });
}

async function signJwtRS256(payload, kid, pem) {
  const header = {
    alg: "RS256",
    typ: "JWT",
    kid
  };

  const encodedHeader = base64url(JSON.stringify(header));
  const encodedPayload = base64url(JSON.stringify(payload));
  const data = `${encodedHeader}.${encodedPayload}`;

  const key = await importPrivateKey(pem);
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(data)
  );

  return `${data}.${base64urlBytes(new Uint8Array(signature))}`;
}

async function importPrivateKey(pem) {
  const clean = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");

  const binary = Uint8Array.from(atob(clean), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "pkcs8",
    binary.buffer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );
}

function base64url(value) {
  return btoa(value)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function base64urlBytes(bytes) {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
