# Aj's crypto tools for Ada

This is just some wrappers that I made for my own benefit and I decided to share it with the world (and also so I can link it into my alire pins).

It provides functions for generating public/private keys & signing with those keys (thanks to [SPARKNaCl](https://github.com/rod-chapman/SPARKNaCl)), password hashing (thanks to [pbkdf2](https://github.com/AntonMeep/pbkdf2)), and random numbers (thanks to [system_random](https://github.com/AntonMeep/system_random)).  Check out the [spec file](src/cryptools.ads) or the [test program](tests/src/cryptools.adb) for documentation and examples.

If you find a bug absolutely report it, but I'm probably not providing any support if it gets super complicated, so use at your own risk!

If you find some more efficient ways to convert between streams (that's heavily what most of these functions are doing) I'm open to knowing how!  Likewise, I'll get rid of the AWS dependency if someone can come up with a better `AWS.Translator.Base64_Encode` :D

I don't plan on publishing this to Alire, so if you want to use this, configure your alire pins.

## Examples

```ada
procedure Sign_String is
   Public_Key : Signing_PK;
   Secret_Key : Signing_SK;
begin
   Initialize (Public_Key, Secret_Key);
   declare
      Signed_Str : constant Byte_Seq := Sign_String ("Hello", Secret_Key);
   begin
      Put_Line ("String is:");
      Put_Line (Open_String (Status, Signed_Str, Public_Key));
   end;
end Sign_String;
```
