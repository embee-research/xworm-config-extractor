"""
Configuration extractor for xworm

Author: Matthew
Twitter: @embee_research

Sha256: c80bbdff42a8264306fc386377873c9bf206657a4051f0412ae00f8e625add69
Sha256: 57ff9c14ceef5ba31b75d8fde541fb37042255e51fb354150b37f7bf9851edd9

Be sure to run this script in the same directory as "dnlib.dll"

usage: xworm-config-extractor.py xworm.bin

Example Output:

Host: 89.117.72.230
Port: 4000
KEY: <123456789>
SPL: <Xwormmm>
Sleep: 3
USBNM: USB.exe
InstallDir: %LocalAppData%
Mutex: n68RPU0TRN0nWk35
LoggerPath: temp\Log.tmp
BTC: 3F9BwXXmgsNNbL5o7XyA7fJD25txcsDyow
ETH: 0x9938A6dE353c60CfD2CF4ac8df4174E9350120e0
TRC: TRC20_Address


"""




import clr, os, sys, hashlib, base64
clr.AddReference(os.getcwd() + "\\dnlib.dll")
from dnlib.DotNet import ModuleDefMD
from dnlib.DotNet.Emit import OpCodes
from Crypto.Cipher import AES

try:
    file_to_open = os.getcwd() + "\\" + sys.argv[1]
    module = ModuleDefMD.Load(file_to_open)
except Exception as e:
    print(e)
    print("Unable to load file, did you provide an argument to a file name?")
    sys.exit(1)

try:
    f = open(os.getcwd() + "\\" + sys.argv[1], "rb")
    data = f.read()
    f.close()
    sha_256 = "".join(x for x in str(hashlib.sha256(data).hexdigest()))
    print("SHA256: " + sha_256)
except:
    pass

#Locate settings class
for mtype in module.GetTypes():
    if str(mtype.Name).endswith("Settings"):
        print("Found Class: " + str(mtype.Name))
        class_name = str(mtype.Name)

#obtain a reference to the settings class
target_type = module.Find(class_name, isReflectionName=True)

config_dict = {}
concat_string = ""
if target_type:
    #Enumerate settings constructor for initial encrypted config values
    constructors = [m for m in target_type.Methods if m.Name in (".cctor", ".ctor")]
    for constructor in constructors:
        if constructor.HasBody:
            ins = constructor.Body.Instructions
            for ptr in range(len(ins)):
                config_name = str(ins[ptr]).split("::")[-1]
                if "stsfld" in str(ins[ptr]):
                    #obtain values that created from multiple strings
                    if "Concat" in str(ins[ptr-1]):
                        #print("concat")
                        for i in range(1,7):
                            line = ins[ptr-i]
                            if "stsfld" in str(line):
                                break
                            if "ldstr" in str(line):
                                concat_string = ins[ptr-i].Operand + concat_string
                                config_dict[config_name] = concat_string
                    elif "ldc.i4" in str(ins[ptr-1]):
                        #Obtain integer config values
                        config_dict[config_name] = str(ins[ptr-1])[-1]     
                
                    elif "ldstr" in str(ins[ptr-1]):
                        #obtain string/base64 config values
                        value = ins[ptr-1].Operand
                        config_dict[config_name] = str(value)
#print(config_dict)

#Calculate md5 of Settings::Mutex
#The md5 is used to create an AES key
md5 = hashlib.md5(bytes(config_dict["Mutex"],'utf-8')).digest()
aes_key = bytearray([0]*32)
aes_key[0:15] = md5[0:16]
aes_key[15:32] = md5[0:16]


#Initialise AES, note that no IV is needed for xworm
cipher = AES.new(aes_key,AES.MODE_ECB)

#Enumerate encrypted settings
for key in config_dict.keys():
    try:
        plaintext = cipher.decrypt(base64.b64decode(config_dict[key]))
        out = ""
        #Remove bad characters
        for i in plaintext:
            out += chr(i)
        out2 = "".join(x for x in out if x.isprintable())
        print(str(key) + ": " + out2)
    except:
        #If unable to decrypt, print the original value
        print(str(key) + ": " + config_dict[key])
        pass







"""

Example IL Instructions that this script is based on


I_0000: ldstr     "ibua+YdsQ1Y7atwvdQ60Vw=="
I_0005: stsfld    string Settings::Host
I_000A: ldstr     "0X9NfiDer/3hAdTkru/rRQ=="
I_000F: stsfld    string Settings::Port
I_0014: ldstr     "sRyRTGC81HAGWhZlQWH1Vg=="
I_0019: stsfld    string Settings::KEY
I_001E: ldstr     "4FzNWW7H7DBZKCI05M9iUg=="
I_0023: stsfld    string Settings::SPL
I_0028: ldc.i4.3
I_0029: stsfld    int32 Settings::Sleep
I_002E: ldstr     "YII5ZM4VMV8rEdVTtiapPQ=="
I_0033: stsfld    string Settings::USBNM
I_0038: ldstr     "%AppData%"
I_003D: stsfld    string Settings::InstallDir
I_0042: ldstr     "mUER53c9ZOF0vhKA"
I_0047: stsfld    string Settings::Mutex
I_004C: ldstr     "temp"
I_0051: call      string [Microsoft.VisualBasic]Microsoft.VisualBasic.Interaction::Environ(string)
I_0056: ldstr     "\\Log.tmp"
I_005B: call      string [mscorlib]System.String::Concat(string, string)
I_0060: stsfld    string Settings::LoggerPath
I_0065: ret



public static object Decrypt(string input)
{
	RijndaelManaged rijndaelManaged = new RijndaelManaged();
	MD5CryptoServiceProvider md5CryptoServiceProvider = new MD5CryptoServiceProvider();
	byte[] array = new byte[32];
	byte[] array2 = md5CryptoServiceProvider.ComputeHash(AlgorithmAES.UTF8SB(Settings.Mutex));
	Array.Copy(array2, 0, array, 0, 16);
	Array.Copy(array2, 0, array, 15, 16);
	rijndaelManaged.Key = array;
	rijndaelManaged.Mode = CipherMode.ECB;
	ICryptoTransform cryptoTransform = rijndaelManaged.CreateDecryptor();
	byte[] array3 = Convert.FromBase64String(input);
	return AlgorithmAES.UTF8BS(cryptoTransform.TransformFinalBlock(array3, 0, array3.Length));
}






"""

