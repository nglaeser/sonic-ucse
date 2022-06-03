use dusk_plonk::jubjub::{JubJubAffine, JubJubExtended, JubJubScalar};
use merlin::{Transcript, TranscriptRng, TranscriptRngBuilder};

pub trait DLogProtocol {
    fn domain_sep(&mut self);
    fn append_point(&mut self, label: &'static [u8], point: &JubJubExtended);
    fn append_scalar(&mut self, label: &'static [u8], scalar: &JubJubScalar);
    fn challenge_scalar(&mut self, label: &'static [u8]) -> JubJubScalar;
}
impl DLogProtocol for Transcript {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"DLogProtocol");
    }
    fn append_point(&mut self, label: &'static [u8], point: &JubJubExtended) {
        let point_bytes: &[u8] = &JubJubAffine::from(point).to_bytes();
        self.append_message(label, point_bytes);
    }
    fn append_scalar(&mut self, label: &'static [u8], scalar: &JubJubScalar) {
        self.append_message(label, &scalar.to_bytes());
    }
    fn challenge_scalar(&mut self, label: &'static [u8]) -> JubJubScalar {
        let mut buf = [0; 64];
        self.challenge_bytes(label, &mut buf);
        JubJubScalar::from_bytes_wide(&buf)
    }
}

// TODO make this for general groups (not just Jubjub), i.e. h: Fr, x: Scalar
pub struct DLogProof {
    pub a: JubJubExtended,
    pub z: JubJubScalar,
}
// prove knowledge of x, the discrete logarithm of h wrt b (i.e., ((h,b), x) s.t. b^x = h)
pub fn prove_dlog(
    transcript: &mut Transcript,
    h: &JubJubExtended,
    b: &JubJubExtended,
    x: &JubJubScalar,
) -> DLogProof {
    // commit to proof label
    transcript.domain_sep();
    // commit to public parameters
    transcript.append_point(b"h", h);
    transcript.append_point(b"b", &b);

    // generate randomness
    let mut rng_builder: TranscriptRngBuilder = transcript.build_rng();
    rng_builder = rng_builder.rekey_with_witness_bytes(b"witness", &x.to_bytes());
    let mut transcript_rng: TranscriptRng = rng_builder.finalize(&mut rand::thread_rng());
    let r = JubJubScalar::random(&mut transcript_rng);

    // round 1 message
    let a: JubJubExtended = b * r;
    transcript.append_point(b"b^r", &a);

    // generate challenge
    let ch: JubJubScalar = transcript.challenge_scalar(b"ch");

    // response
    let z: JubJubScalar = r + ch * x;
    DLogProof { a, z }
}
pub enum ProofError {
    GenericError,
}
pub fn vrfy_dlog(
    transcript: &mut Transcript,
    h: &JubJubExtended,
    b: &JubJubExtended,
    proof: DLogProof,
) -> Result<(), ProofError> {
    // commit to proof label
    transcript.domain_sep();
    // commit to public parameters
    transcript.append_point(b"h", h);
    transcript.append_point(b"b", &b);

    // round 1 message
    transcript.append_point(b"b^r", &proof.a);
    // generate challenge
    let ch: JubJubScalar = transcript.challenge_scalar(b"ch");

    let lhs = b * proof.z;
    let rhs = proof.a + h * ch;
    match lhs == rhs {
        true => Ok(()),
        false => Err(ProofError::GenericError),
    }
}
