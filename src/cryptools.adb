pragma Ada_2022;
with AWS.Translator;
with System_Random;
with PBKDF2;
with Interfaces;

package body Cryptools is
   --  For generating random stream elements
   package Streams_Random is new System_Random
      (Element       => Ada.Streams.Stream_Element,
         Index         => Ada.Streams.Stream_Element_Offset,
         Element_Array => Ada.Streams.Stream_Element_Array);

   function Gen_Random (Length : Positive)
      return Ada.Streams.Stream_Element_Array
   is
      --  Create a new ada string that will be returned.
      Result : aliased Ada.Streams.Stream_Element_Array :=
               [0 .. Ada.Streams.Stream_Element_Offset (Length - 1) => 0];
   begin
      --  Fill with random data
      Streams_Random.Random (Result);
      return Result;
   end Gen_Random;

   --  Initialize secret / public key pair
   procedure Initialize (Public_Key : out SPARKNaCl.Sign.Signing_PK;
                         Secret_Key : out SPARKNaCl.Sign.Signing_SK)
   is
   begin
      SPARKNaCl.Sign.Keypair
         (To_Byte_Seq (Gen_Random (32)),
          Public_Key,
          Secret_Key);
   end Initialize;

   function Sign_Payload
      (Message : Ada.Streams.Stream_Element_Array;
       Secret_Key : SPARKNaCl.Sign.Signing_SK)
      return SPARKNaCl.Byte_Seq
   is
      use SPARKNaCl;
      use Interfaces;
      Payload : constant Byte_Seq := To_Byte_Seq (Message);
      Result  : Byte_Seq (Payload'First .. Payload'Last + 64) := (others => 0);
   begin
      SPARKNaCl.Sign.Sign (Result, Payload, Secret_Key);
      return Result;
   end Sign_Payload;

   --  Sign a string with a secret key
   function Sign_String
      (Message : String;
       Secret_Key : SPARKNaCl.Sign.Signing_SK)
      return SPARKNaCl.Byte_Seq
   is
      use SPARKNaCl;
      use Interfaces;
      Payload : constant Byte_Seq := To_Byte_Seq (Message);
      Result  : Byte_Seq (Payload'First .. Payload'Last + 64) := (others => 0);
   begin
      SPARKNaCl.Sign.Sign (Result, Payload, Secret_Key);
      return Result;
   end Sign_String;

   function Open_Payload
      (Status     : out Boolean;
       Payload    : SPARKNaCl.Byte_Seq;
       Public_Key : SPARKNaCl.Sign.Signing_PK)
      return Ada.Streams.Stream_Element_Array
   is
      ML : SPARKNaCl.I32;
      Raw_Result  : SPARKNaCl.Byte_Seq (Payload'First .. Payload'Last) :=
                     (others => 0);
   begin
      SPARKNaCl.Sign.Open
        (M      => Raw_Result,
         Status => Status,
         MLen   => ML,
         SM     => Payload,
         PK     => Public_Key);
      if Status then
         declare
            use Interfaces;
            Result : constant Ada.Streams.Stream_Element_Array :=
                        To_Element_Array (Raw_Result(Raw_Result'First .. ML-1));
         begin
            return Result;
         end;
      else
         return [0 .. 0 => 0];
      end if;
   end Open_Payload;

   function Open_String
      (Status : out Boolean;
       Payload : SPARKNaCl.Byte_Seq;
       Public_Key : SPARKNaCl.Sign.Signing_PK)
      return String
   is
      ML : SPARKNaCl.I32;
      Raw_Result  : SPARKNaCl.Byte_Seq (Payload'First .. Payload'Last) :=
                     [others => 0];
   begin
      SPARKNaCl.Sign.Open
        (M      => Raw_Result,
         Status => Status,
         MLen   => ML,
         SM     => Payload,
         PK     => Public_Key);
      if Status then
         declare
            Result : constant String :=
                        [for X of Raw_Result => Character'Val (X)];
         begin
            return Result (Result'First .. Integer (ML));
         end;
      else
         return "";
      end if;
   end Open_String;

   function Gen_Salt return String is
      --  I'm writing this out instead of using Gen_Random to save on a
      --  function call
      Salt_Values : aliased Ada.Streams.Stream_Element_Array := [0 .. 15 => 0];
   begin
      Streams_Random.Random (Salt_Values); --  Fill with random data
      return To_Base64_String (Salt_Values);
   end Gen_Salt;

   function Gen_Hash
      (Password : String;
       Salt     : String;
       Work     : Positive := 600_000;
       Pepper   : String := "")
      return String
   is
      --  Calculate Hash.
      Hash : constant Ada.Streams.Stream_Element_Array :=
               PBKDF2.PBKDF2_HMAC_SHA_256
                  (Password => Password & Pepper,
                   Salt => Salt,
                   Iterations => Work);
   begin
      return To_Base64_String (Hash);
   end Gen_Hash;

   function To_Base64_String
      (S : Ada.Streams.Stream_Element_Array) return String
   is
      use AWS.Translator;
   begin
      return String (Base64_Encode (Data => S, Mode => MIME));
   end To_Base64_String;

   function To_Base64_String (S : SPARKNaCl.Byte_Seq) return String
   is (To_Base64_String (To_Element_Array (S)));

   function From_Base64_String (S : String)
      return Ada.Streams.Stream_Element_Array
   is
      use AWS.Translator;
   begin
      return Base64_Decode (Base64_String (S));
   end From_Base64_String;

   function To_Byte_Seq (Data : Ada.Streams.Stream_Element_Array)
      return SPARKNaCl.Byte_Seq
   is ([for D of Data => SPARKNaCl.Byte (D)]);

   function To_Element_Array (Data : SPARKNaCl.Byte_Seq)
      return Ada.Streams.Stream_Element_Array
   is
      Result : Ada.Streams.Stream_Element_Array
         (Ada.Streams.Stream_Element_Offset (Data'First) ..
          Ada.Streams.Stream_Element_Offset (Data'Last));
   begin
      for D in Data'Range loop
         Result (Ada.Streams.Stream_Element_Offset (D)) :=
            Ada.Streams.Stream_Element (Data (D));
      end loop;
      return Result;
   end To_Element_Array;

end Cryptools;