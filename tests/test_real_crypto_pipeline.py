"""
Security and Integrity Tests for Real GF(2^8) Cryptographic Pipeline.
Verifies that:
1. No plaintext is stored in the vault.
2. Tokens contain real GF(2^8) affine ciphertexts.
3. Lagrange interpolation and Affine inversion are both actively used and cross-verified.
4. Tampering with shares causes mathematical reconstruction failure.
"""

from blindagent.pipeline import BlindPipeline


def test_zero_plaintext_storage():
    pipeline = BlindPipeline(sss_threshold=3, sss_total=5)
    prompt = "Authorize transfer for master_key: TitaniumVaultSecret99! with amount $25,000."
    res = pipeline.execute(prompt)

    # 1. Verify vault holds NO plaintext
    for token, entity in pipeline.blinder.vault.items():
        assert not hasattr(entity, "original_value"), "Security failure: original_value still exists on entity!"
        assert "TitaniumVaultSecret99!" not in str(entity.__dict__.values()), "Plaintext found in entity fields!"

    # 2. Verify token on wire contains real GF(2^8) ciphertext
    assert "TitaniumVaultSecret99!" not in res.wire_payload
    assert "AFF8_" in res.wire_payload

    # 3. Verify final output was correctly reconstructed via C engine
    assert "TitaniumVaultSecret99!" in res.final_output
    print("test_zero_plaintext_storage PASSED!")


def test_mathematical_cross_verification():
    pipeline = BlindPipeline(sss_threshold=3, sss_total=5)
    prompt = "Check status of SSN: 987-65-4321."
    pipeline.execute(prompt)

    for token, entity in pipeline.blinder.vault.items():
        # Lagrange reconstruction from SSS shares
        from_sss = entity.reconstruct_secret(pipeline.blinder.sss)
        # Affine inversion via Fermat's Little Theorem (alpha^254)
        from_affine = entity.unblind_affine_secret()

        assert from_sss == "987-65-4321"
        assert from_affine == "987-65-4321"
        assert from_sss == from_affine

    print("test_mathematical_cross_verification PASSED!")


def test_share_corruption_fails_reconstruction():
    pipeline = BlindPipeline(sss_threshold=3, sss_total=5)
    prompt = "Access api_secret: SuperSecretToken12345."
    pipeline.execute(prompt)

    for token, entity in pipeline.blinder.vault.items():
        # Corrupt one share by altering its hex bytes
        corrupted_shares = list(entity.shares)
        first_share = corrupted_shares[0]
        # Modify the last character of the share hex
        corrupted_share = first_share[:-1] + ('0' if first_share[-1] != '0' else '1')
        corrupted_shares[0] = corrupted_share

        # Reconstructing with corrupted share must yield scrambled junk, not original secret
        junk = pipeline.blinder.sss.combine_text(corrupted_shares[:3])
        assert junk != "SuperSecretToken12345", "Reconstruction should fail when share is tampered!"

    print("test_share_corruption_fails_reconstruction PASSED!")


if __name__ == "__main__":
    test_zero_plaintext_storage()
    test_mathematical_cross_verification()
    test_share_corruption_fails_reconstruction()
    print("\nALL CRYPTOGRAPHIC INTEGRITY TESTS PASSED 100%!")
