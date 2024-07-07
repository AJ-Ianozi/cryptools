pragma Ada_2022;
with Ada.Streams;
with SPARKNaCl;
with SPARKNaCl.Sign;
package Cryptools is
   --  ------------------------------------------------------------------------
   --  Randomness related functions.
   --  ------------------------------------------------------------------------

   --  Generates random data into a steram_element array of "Length" bytes
   function Gen_Random (Length : Positive)
      return Ada.Streams.Stream_Element_Array;

   --  ------------------------------------------------------------------------
   --  Keypair signing
   --  ------------------------------------------------------------------------

   --  Initialize secret / public key pair
   procedure Initialize (Public_Key : out SPARKNaCl.Sign.Signing_PK;
                         Secret_Key : out SPARKNaCl.Sign.Signing_SK);

   --  Sign an element array with a secret key.
   function Sign_Payload
      (Message : Ada.Streams.Stream_Element_Array;
       Secret_Key : SPARKNaCl.Sign.Signing_SK)
      return SPARKNaCl.Byte_Seq;

   --  Sign a string with a secret key
   function Sign_String
      (Message : String;
       Secret_Key : SPARKNaCl.Sign.Signing_SK)
      return SPARKNaCl.Byte_Seq;

   --  Read a signed payload.
   function Open_Payload
      (Status     : out Boolean;
       Payload    : SPARKNaCl.Byte_Seq;
       Public_Key : SPARKNaCl.Sign.Signing_PK)
      return Ada.Streams.Stream_Element_Array;

   --  Read a signed string.
   function Open_String
      (Status     : out Boolean;
       Payload    : SPARKNaCl.Byte_Seq;
       Public_Key : SPARKNaCl.Sign.Signing_PK)
      return String;

   --  ------------------------------------------------------------------------
   --  Password related functions.
   --  ------------------------------------------------------------------------

   --  Creates a random salt.
   function Gen_Salt return String;

   --  Generates a pbkdf2 hashed password based on password & salt
   --  Work is how many iterations, defaults to 600k
   --  Pepper should be a hardcoded constant in your source code, if using.
   function Gen_Hash
      (Password : String;
       Salt     : String;
       Work     : Positive := 600_000;
       Pepper   : String := "")
      return String;

   --  ------------------------------------------------------------------------
   --  Conversion functions that may be helpful. The library uses them too.
   --  ------------------------------------------------------------------------

   --  Convert stream element array to base64 string
   function To_Base64_String
      (S : Ada.Streams.Stream_Element_Array)
      return String;

   --  Convert byte sequence to base64 string
   function To_Base64_String
      (S : SPARKNaCl.Byte_Seq)
      return String;

   --  Convert Base64 string to stream element array
   function From_Base64_String (S : String)
      return Ada.Streams.Stream_Element_Array;

   --  Convert stream element array to byte sequence
   function To_Byte_Seq (Data : Ada.Streams.Stream_Element_Array)
      return SPARKNaCl.Byte_Seq;

   --  Convert byte sequence to stream element array
   function To_Element_Array (Data : SPARKNaCl.Byte_Seq)
      return Ada.Streams.Stream_Element_Array;
end Cryptools;
