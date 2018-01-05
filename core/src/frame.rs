
use std::io;
use super::errors::Result;
use signature::Signature;
use message::{Message, PubKey};
use ring;

/// The `Frame` wraps the [`Message`] and provides its signature.
///
/// Changing the version field means changing the format of the `Frame`
///
/// [`Message`]: struct.Message.html
#[derive(Debug)]
pub struct Frame {
    /// a special value that is always 1 for this given `Frame`.
    pub version: u32,

    /// the serialized format of the [`Message`].
    /// [`Message`]: struct.Message.html
    pub message: Vec<u8>,

    /// The Ed25519 signature of the `message` field.
    pub signature: Signature,
}

impl Frame {
    pub fn new_signed(message: &Message, keypair: &ring::signature::Ed25519KeyPair) -> Result<Frame>
    {
        let mut buffer: Vec<u8> = Vec::new();
        message.write(&mut buffer)?;
        let signature = keypair.sign(Frame::digest(&buffer).as_ref());
        Ok(Frame {
            version: 1,
            message: buffer,
            signature: Signature::new(signature.as_ref())?,
        })
    }

    pub fn verify(&self, pubkey: &PubKey) -> bool
    {
        use ::untrusted::Input;
        let digest = Frame::digest(&self.message);
        let message = Input::from(digest.as_ref());

        let signature = Input::from(&self.signature.0[..]);
        let pubkey_bytes = Input::from(&pubkey.0[..]);
        ring::signature::verify(&ring::signature::ED25519,
                                pubkey_bytes,
                                message,
                                signature).is_ok()
    }

    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<u32>
    {
        use rmp::encode;
        encode::write_array_len(buffer, 3)?;
        encode::write_uint(buffer, 1)?; // version
        encode::write_bin(buffer, self.message.as_ref())?;
        encode::write_bin(buffer, &self.signature.0[..])?;
        Ok(0u32)
    }

    pub fn read<R>(buffer: &mut R) -> Result<Frame>
        where R: io::Read
    {
        use rmp::decode;

        let array_len = decode::read_array_len(buffer)?;
        assert_eq!(array_len, 3);
        let version = decode::read_int::<u32, R>(buffer)?;
        assert_eq!(version, 1);

        let message_len = decode::read_bin_len(buffer)?;
        let mut message_buffer = vec![0u8; message_len as usize];
        buffer.read_exact(&mut message_buffer[..])?;

        let signature_len = decode::read_bin_len(buffer)?;
        assert_eq!(signature_len, 64);
        let mut signature_buffer = [0u8; 64];
        buffer.read_exact(&mut signature_buffer[..])?;

        Ok(Frame {
            version: 1,
            message: message_buffer,
            signature: Signature(signature_buffer),
        })
    }

    fn digest(buffer: &Vec<u8>) -> ring::digest::Digest
    {
        ring::digest::digest(&ring::digest::SHA512, &buffer[..])
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_comparison()
    {
        assert!(Signature([0u8; 64]) == Signature([0u8; 64]));
        assert!(Signature([1u8; 64]) != Signature([0u8; 64]));
        assert!(Signature([42u8; 64]) == Signature([42u8; 64]));
    }

    mod encoding_and_decoding {
        use super::*;

        #[test]
        fn simple_back_and_forth()
        {
            let frame = Frame {
                version: 1,
                message: vec![0x42, 0x2a, 0x66],
                signature: Signature([42u8; 64]),
            };

            let decoded_frame = encode_decode(&frame);

            assert_eq!(frame.version, decoded_frame.version);
            assert_eq!(frame.message, decoded_frame.message);
            assert_eq!(frame.signature, decoded_frame.signature);
        }

    }

    use ::load_key;

    #[test]
    fn signed_frame_can_be_created_from_message_and_keypair()
    {
        use ::message::PubKey;
        let frame = create_test_frame();
        let pubkey = PubKey::new(TEST_PUBKEY);
        assert!(frame.verify(&pubkey))
    }

    #[test]
    fn signed_frame_can_be_written_back_and_forth_and_stays_signed()
    {
        let frame = create_test_frame();
        let decoded_frame = encode_decode(&frame);

        let pubkey = PubKey::new(TEST_PUBKEY);
        assert!(decoded_frame.verify(&pubkey))
    }

    #[test]
    fn verification_should_fail_for_signed_frame_with_different_pubkey()
    {
        use ::message::{PubKey, ContentType, Message};
        let message = Message {
            author: PubKey::new(TEST_PUBKEY),
            parent: None,
            content_type: ContentType::Blob,
            content: vec![42u8, 44u8],
        };
        let privkey = load_key(TEST_PRIVKEY).expect("could not load privkey");
        let frame = Frame::new_signed(&message, &privkey).expect("could not create Frame");

        let wrong_pubkey = PubKey::new(WRONG_PUBKEY);
        assert!(!frame.verify(&wrong_pubkey));
    }

    fn create_test_frame() -> Frame
    {
        let message = create_test_message();
        let privkey = load_key(TEST_PRIVKEY).expect("could not load privkey");
        Frame::new_signed(&message, &privkey).expect("could not create Frame")
    }

    fn create_test_message() -> Message
    {
        use ::message::{PubKey, ContentType, Message};
        Message {
            author: PubKey::new(TEST_PUBKEY),
            parent: None,
            content_type: ContentType::Blob,
            content: vec![42u8, 44u8],
        }
    }

    fn encode_decode(frame: &Frame) -> Frame {
        let mut buffer: Vec<u8> = Vec::new();
        frame.write(&mut buffer).expect("Write failed");
        Frame::read(&mut io::Cursor::new(buffer)).expect("Read failed")
    }

    static TEST_PUBKEY: &'static [u8] = &[
        0x84, 0x98, 0x39, 0xe6, 0x01, 0xe2, 0x84, 0x10,
        0xc9, 0x77, 0xfa, 0x77, 0x63, 0xf6, 0xab, 0x19,
        0x16, 0x7d, 0xde, 0x7a, 0xa0, 0x38, 0x27, 0xaa,
        0x8c, 0x6f, 0x28, 0x87, 0x8e, 0xb6, 0x31, 0x8e];

    static WRONG_PUBKEY: &'static [u8] = &[
        0x42, 0x42, 0x42, 0xe6, 0x01, 0xe2, 0x84, 0x10,
        0xc9, 0x77, 0xfa, 0x77, 0x63, 0xf6, 0xab, 0x19,
        0x16, 0x7d, 0xde, 0x7a, 0xa0, 0x38, 0x27, 0xaa,
        0x8c, 0x6f, 0x28, 0x87, 0x8e, 0xb6, 0x31, 0x8e];

    static TEST_PRIVKEY: &'static [u8] = &[
        0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        0x68, 0xc4, 0xd9, 0xb0, 0x77, 0xd5, 0x0b, 0xe7,
        0xb1, 0xf3, 0xf5, 0xf1, 0x5b, 0x76, 0x8d, 0xae,
        0x17, 0xe3, 0xd3, 0x2c, 0x3f, 0x18, 0xeb, 0xfe,
        0x5b, 0x9a, 0x38, 0xa2, 0x45, 0x4a, 0x9c, 0x84,
        0xa1, 0x23, 0x03, 0x21, 0x00, 0x84, 0x98, 0x39,
        0xe6, 0x01, 0xe2, 0x84, 0x10, 0xc9, 0x77, 0xfa,
        0x77, 0x63, 0xf6, 0xab, 0x19, 0x16, 0x7d, 0xde,
        0x7a, 0xa0, 0x38, 0x27, 0xaa, 0x8c, 0x6f, 0x28,
        0x87, 0x8e, 0xb6, 0x31, 0x8e,
    ];
}
