use alloy::sol;

sol! {
    #[derive(Debug)]
    struct WebAuthnP256 {
        /// The WebAuthn authenticator data.
        /// See: https://www.w3.org/TR/webauthn-2/#dom-authenticatorassertionresponse-authenticatordata.
        bytes authenticatorData;
        /// The WebAuthn client data JSON.
        /// See: https://www.w3.org/TR/webauthn-2/#dom-authenticatorresponse-clientdatajson.
        string clientDataJSON;
        /// Start index of "challenge":"..." in `clientDataJSON`.
        uint256 challengeIndex;
        /// Start index of "type":"..." in `clientDataJSON`.
        uint256 typeIndex;
        /// The r value of secp256r1 signature.
        bytes32 r;
        /// The s value of secp256r1 signature.
        bytes32 s;
    }
}
