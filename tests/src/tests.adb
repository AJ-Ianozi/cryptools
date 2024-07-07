pragma Ada_2022;
with Ada.Assertions; use Ada.Assertions;
with Cryptools;      use Cryptools;
with SPARKNaCl;      use SPARKNaCl;
with SPARKNaCl.Sign; use SPARKNaCl.Sign;
with Ada.Streams;    use Ada.Streams;
with Ada.Text_IO; use Ada.Text_IO;
procedure Tests is
   Known_String : constant String :=
                     "The quick brown fox jumps over the lazy dog.1234!!!";
   Random_Salt : constant String := Gen_Salt;
   Known_Array : constant Stream_Element_Array (0 .. 255) := [0 => 16#55#, others => 16#aa#];
   Known_Bytes : constant Byte_Seq (0 .. 255) := [0 => 16#55#, others => 16#aa#];
   Known_Base64_Str : constant String :=
      "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4xMjM0ISEh";
   Msg_Base64 : constant String :=
      "Vaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq" &
      "qg==";

      Public_Key : Signing_PK;
      Secret_Key : Signing_SK;
      Status : Boolean;
begin
   --  Test conversions
   Assert (Known_Array = To_Element_Array (Known_Bytes));
   Assert (Known_Bytes = To_Byte_Seq (Known_Array));
   Assert (Msg_Base64  = To_Base64_String (Known_Bytes));
   Assert (Msg_Base64  = To_Base64_String (Known_Array));
   Assert (To_Element_Array (Known_Bytes) = From_Base64_String (Msg_Base64));

   --  Test hashing
   Assert (Gen_Hash (Known_String, Random_Salt) = Gen_Hash (Known_String, Random_Salt));

   --  Test signing key
   Initialize (Public_Key, Secret_Key);
   declare
      Signed_Str : constant Byte_Seq := Sign_String (Known_String, Secret_Key);
      Payload : constant Byte_Seq := Sign_Payload (Known_Array, Secret_Key);
   begin
      Assert (Known_Array = Open_Payload (Status, Payload, Public_Key));
      Assert (Known_String = Open_String (Status, Signed_Str, Public_Key));
      --  This converts known_string's actual bytes against known base64
      Assert (Known_Base64_Str = To_Base64_String (Open_Payload (Status, Signed_Str, Public_Key)));
   end;
   Put_Line ("All tests passed.");
end Tests;
