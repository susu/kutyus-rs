
use std::io;
use std::fmt;

use ::errors::Result;

/// An Ed25519 public key, also used as type of author in [`Message`]
/// [`Message`]: struct.Message.html
#[derive(PartialEq)]
pub struct PubKey(pub [u8; 32]);

impl fmt::Debug for PubKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:x} ", byte)?;
        }
        Ok(())
    }
}

impl PubKey {
    /// Creates a new `PubKey` from a slice
    ///
    /// TODO: Check slice length?
    pub fn new(array: &[u8]) -> PubKey
    {
        let mut pubkey = [0u8; 32];
        for (&x, p) in array.iter().zip(pubkey.iter_mut()) {
            *p = x;
        }
        PubKey(pubkey)
    }
}


/// The SHA-512 digest of the parent [`Message`]'s serialized format
///
/// TODO use fixed-length array
/// [`Message`]: struct.Message.html
#[derive(Debug, PartialEq)]
pub struct ParentHash(pub Vec<u8>);

impl ParentHash {
    /// Reads an msgpack-formatted optional `ParentHash`
    ///
    /// * zero-length array means lack of the `ParentHash`
    /// * one-length array means that the `ParentHash` is defined
    ///
    /// The length of the binary array must be 64 bytes
    pub fn read<R>(buffer: &mut R) -> Result<Option<ParentHash>>
        where R: io::Read
    {
        use rmp::decode;
        let array_length = decode::read_array_len(buffer)?;
        if array_length == 0 {
            // zero length array means None
            Ok(None)
        } else {
            // SHA-512 must have length of 64 bytes
            let hash_length = decode::read_bin_len(buffer)?;
            assert_eq!(hash_length, 64); // TODO proper error handling
            let mut hash_buffer = vec![0u8; 64];
            buffer.read_exact(&mut hash_buffer[..])?;
            Ok(Some(ParentHash(hash_buffer)))
        }
    }
}


#[derive(Debug, PartialEq)]
pub enum ContentType {
    Blob,
    Custom(Vec<u8>),
}

impl ContentType {
    pub fn read<R>(buffer: &mut R) -> Result<ContentType>
        where R: io::Read
    {
        use rmp::decode;
        let length = decode::read_bin_len(buffer)?;
        let mut data = vec![0u8; length as usize];
        buffer.read_exact(&mut data[..])?;
        Ok(if data.len() == 1 && data[0] == 0u8 {
            ContentType::Blob
        } else {
            ContentType::Custom(data)
        })
    }

    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<u32>
    {
        use rmp::encode;

        match self {
            &ContentType::Blob => encode::write_bin(buffer, &[0u8])?,
            &ContentType::Custom(ref data) => encode::write_bin(buffer, data)?
        }

        Ok(0u32)
    }
}

/// The actual message
///
#[derive(Debug)]
pub struct Message {
    /// The Ed25519 public key of the author
    pub author: PubKey,

    /// SHA-512 of the msgpack serialized format of the parent message
    ///
    /// It can be None only in case of the root node.
    /// All child nodes must fill this value.
    pub parent: Option<ParentHash>,

    /// Application-specific type identifier
    ///
    /// It determines how the content should be interpreted
    pub content_type: ContentType,

    /// The actual payload of the `Message`
    pub content: Vec<u8>,
}

impl Message {
    /// Encodes the Message in the msgpack format
    ///
    /// The format is: an array with 4 items:
    ///
    /// 1. author's public key (32 bytes binary)
    /// 2. hash of parent node, see [`ParentHash`] for details
    /// 3. content type (binary, variable length)
    /// 4. content: (binary, variable length)
    ///
    /// [`ParentHash`]: struct.ParentHash.html
    pub fn write(&self, buffer: &mut Vec<u8>) -> Result<u32>
    {
        use rmp::encode;
        encode::write_array_len(buffer, 4)?;

        encode::write_bin(buffer, self.author.0.as_ref())?;

        self.write_parent(buffer)?;
        self.content_type.write(buffer)?;

        encode::write_bin(buffer, self.content.as_ref())?;

        Ok(0u32)
    }

    /// Encodes the Message from the msgpack format
    fn write_parent(&self, buffer: &mut Vec<u8>) -> Result<u32>
    {
        use rmp::encode;
        match self.parent {
            Some(ref hash) => {
                encode::write_array_len(buffer, 1)?;
                encode::write_bin(buffer, hash.0.as_ref())?;
            },
            None => { encode::write_array_len(buffer, 0)?; }
        };

        Ok(0u32)
    }

    pub fn read<R>(buffer: &mut R) -> Result<Message>
        where R: io::Read
    {
        use rmp::decode;
        let _array_size = decode::read_array_len(buffer)?;
        assert_eq!(_array_size, 4); // TODO error handling TODO must be 4

        let author_bin_length = decode::read_bin_len(buffer)?;
        assert_eq!(author_bin_length, 32); // TODO error handling

        let mut author_buffer = [0u8; 32];
        buffer.read_exact(&mut author_buffer)?;

        let parent_hash: Option<ParentHash> = ParentHash::read(buffer)?;

        let content_type = ContentType::read(buffer)?;

        let content_length = decode::read_bin_len(buffer)?;
        let mut content_vec = vec![0u8; content_length as usize];
        buffer.read_exact(&mut content_vec[..])?;

        let msg = Message {
            author: PubKey(author_buffer),
            parent: parent_hash,
            content_type: content_type,
            content: content_vec
        };

        Ok(msg)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    mod encoding_and_decoding {
        use super::*;

        #[test]
        fn should_result_the_same_message()
        {
            let message = Message {
                author: PubKey([1u8; 32]),
                parent: None,
                content_type: ContentType::Custom(vec![43u8]),
                content: vec![255u8, 254u8],
            };


            let decoded_message = encode_decode(&message);

            assert_eq!(message.author, decoded_message.author);
            assert_eq!(message.content_type, decoded_message.content_type);
            assert_eq!(message.content, decoded_message.content);
            assert_eq!(message.parent, decoded_message.parent);
        }

        #[test]
        fn should_result_the_same_parent_hash_if_defined()
        {
            let message = Message {
                author: PubKey([1u8; 32]),
                parent: Some(ParentHash(vec![2u8; 64])),
                content_type: ContentType::Custom(vec![42u8]),
                content: vec![255u8, 255u8],
            };
            let decoded_message = encode_decode(&message);
            assert_eq!(message.parent, decoded_message.parent);
        }

        #[test]
        fn should_result_the_same_parent_hash_if_undefined()
        {
            let message = Message {
                author: PubKey([1u8; 32]),
                parent: None,
                content_type: ContentType::Custom(vec![42u8]),
                content: vec![42u8, 44u8],
            };
            let decoded_message = encode_decode(&message);
            assert_eq!(message.parent, decoded_message.parent);
        }

        fn encode_decode(message: &Message) -> Message {
            let mut buffer: Vec<u8> = Vec::new();
            message.write(&mut buffer).expect("Write failed");
            debug(&buffer);

            Message::read(&mut io::Cursor::new(buffer)).expect("Read failed")
        }

        fn debug(buffer: &Vec<u8>)
        {
            print!("\n % BUF % # # @ => [\n    ");
            for (index, byte) in buffer.iter().enumerate() {
                print!("0x{:02X}, ", byte);
                if index % 4 == 3 { print!("  "); }
                if index % 8 == 7 { print!("\n    "); }
            }
            println!("]\n");
        }
    }
}
