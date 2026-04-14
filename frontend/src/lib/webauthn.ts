function base64UrlToBuffer(value: string): ArrayBuffer {
  if (!value) {
    throw new Error('Invalid WebAuthn payload: missing base64url value')
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4)
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function mapCredentialResponse(response: AuthenticatorResponse): Record<string, unknown> {
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse
    return {
      clientDataJSON: bufferToBase64Url(attestation.clientDataJSON),
      attestationObject: bufferToBase64Url(attestation.attestationObject)
    }
  }

  const assertion = response as AuthenticatorAssertionResponse
  return {
    clientDataJSON: bufferToBase64Url(assertion.clientDataJSON),
    authenticatorData: bufferToBase64Url(assertion.authenticatorData),
    signature: bufferToBase64Url(assertion.signature),
    userHandle: assertion.userHandle ? bufferToBase64Url(assertion.userHandle) : null
  }
}

function credentialToJson(credential: PublicKeyCredential): Record<string, unknown> {
  return {
    id: credential.id,
    rawId: bufferToBase64Url(credential.rawId),
    response: mapCredentialResponse(credential.response),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults()
  }
}

function normalizeCreationOptions(options: Record<string, unknown>): PublicKeyCredentialCreationOptions {
  const root = (options.publicKey ?? options) as unknown as PublicKeyCredentialCreationOptions
  const publicKey = { ...root }

  publicKey.challenge = base64UrlToBuffer(publicKey.challenge as unknown as string)
  publicKey.user = {
    ...(publicKey.user as PublicKeyCredentialUserEntity),
    id: base64UrlToBuffer((publicKey.user as PublicKeyCredentialUserEntity).id as unknown as string)
  }

  if (publicKey.excludeCredentials) {
    publicKey.excludeCredentials = publicKey.excludeCredentials.map((item) => ({
      ...item,
      id: base64UrlToBuffer(item.id as unknown as string)
    }))
  }

  return publicKey
}

function normalizeRequestOptions(options: Record<string, unknown>): PublicKeyCredentialRequestOptions {
  const root = (options.publicKey ?? options) as unknown as PublicKeyCredentialRequestOptions
  const publicKey = { ...root }

  publicKey.challenge = base64UrlToBuffer(publicKey.challenge as unknown as string)

  if (publicKey.allowCredentials) {
    publicKey.allowCredentials = publicKey.allowCredentials.map((item) => ({
      ...item,
      id: base64UrlToBuffer(item.id as unknown as string)
    }))
  }

  return publicKey
}

export async function createPasskeyCredential(options: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support WebAuthn')
  }

  const credential = (await navigator.credentials.create({
    publicKey: normalizeCreationOptions(options)
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('Passkey creation was cancelled')
  }

  return credentialToJson(credential)
}

export async function getPasskeyCredential(options: Record<string, unknown>): Promise<Record<string, unknown>> {
  if (!window.PublicKeyCredential) {
    throw new Error('This browser does not support WebAuthn')
  }

  const credential = (await navigator.credentials.get({
    publicKey: normalizeRequestOptions(options)
  })) as PublicKeyCredential | null

  if (!credential) {
    throw new Error('Passkey sign-in was cancelled')
  }

  return credentialToJson(credential)
}
