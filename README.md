# Grand Larceny Auto — TryHackMe Writeup

**Room:** [tryhackme.com/room/grandlarcenyauto](https://tryhackme.com/room/grandlarcenyauto)
**Category:** Reverse Engineering / Godot (C#) game binary
**Difficulty:** Static analysis only — no Windows VM required

## TL;DR

The room ships a small Godot game where a "Safehouse Vault" is supposed to unlock once
the player reaches 6 wanted stars. The unlock check and the crypto key used to decrypt
the flag are **not** tied to the same condition — the check accepts 6 *or more* stars,
but the decryption key is derived from whatever your star count is *at that exact
moment*. Only a player sitting at **exactly 6** stars gets a key that actually matches
the sealed blob. Anyone who plays normally blows past 6 stars and gets garbage instead
of the flag.

The whole thing is solvable through static analysis + a small C# reflection harness,
without ever launching the game.

---

## 1. Recon — what's actually in the zip?

```
GrandLarcenyAuto-windows/
├── GrandLarcenyAuto.exe
├── GrandLarcenyAuto.pck                 <- 2.3 KB (!)
└── data_GrandLarcenyAuto_windows_x86_64/
    ├── GrandLarcenyAuto.dll             <- 93 KB, the actual game logic
    ├── GodotSharp.dll
    ├── coreclr.dll, hostfxr.dll, ...
    └── a full .NET 8 CoreCLR runtime + System.*.dll pile
```

The `.pck` file is where Godot normally stores all game assets/scripts — a 2.3 KB
`.pck` means there's basically nothing there. Combined with the fact that the full
.NET 8 CoreCLR runtime is bundled, this tells you the game is a **Godot C# project**,
and all the real logic lives in the single managed `GrandLarcenyAuto.dll`. That's much
friendlier to reverse than picking apart packed Godot resources.

## 2. First pass with `strings`

```bash
strings -n 6 GrandLarcenyAuto.dll | grep -iE "flag|vault|safehouse|unlock" | sort -u
```

```
CheckCrimesAndVault
MakeVault
SafehouseVault
TryVault
UnlockStars
vaultDot
vaultDotLabel
vaultPos
```

`SafehouseVault` / `TryOpen` / `UnlockStars` point straight at a dedicated vault class
gated on wanted-star count. That's the target.

## 3. Getting IL out of the DLL

No dnSpy/ILSpy on hand, so `monodis` (from `mono-utils`) does the job — it dumps full
CIL text, which is enough to work with:

```bash
apt-get install -y mono-utils
monodis GrandLarcenyAuto.dll > game_disasm.il
grep -n "SafehouseVault" game_disasm.il
```

That points to the class definition:

```il
.class public auto ansi beforefieldinit SafehouseVault
    extends [System.Runtime]System.Object
{
    .field private static literal  int32 UnlockStars = int32(0x00000006)
    .field private initonly  class GrandLarcenyAuto.PlayerState player
    .field private static initonly  unsigned int8[] SealedBlob
    ...
```

`UnlockStars = 6`, a reference to the player state, and a `SealedBlob` byte array —
so something in there is encrypted and only decrypts correctly under the right
conditions.

## 4. Wading through the obfuscation

`TryOpen()` is control-flow-flattened: a fake "state" integer gets XOR'd/multiplied
and used to jump between switch blocks in non-linear order. String and byte-array
literals are also encrypted, resolved at runtime via a method whose *name* is a string
of zero-width Unicode characters (invisible in a normal `grep`, but visible once you
switch to `grep -P` with a Unicode range).

You don't need to fully reverse the resolver's math — tracing what value the method
ultimately *returns* is enough to see the real logic:

```csharp
public string TryOpen()
{
    if (player.WantedStars < 6)
        return "The vault stays shut. ... (You need SIX stars. Good luck.)";

    byte[] key   = CryptoUtil.DeriveKey(player.WantedStars);
    byte[] plain = CryptoUtil.Xor(SealedBlob, key);
    string message = Encoding.UTF8.GetString(plain);
    Array.Clear(plain);
    Array.Clear(key);
    return "VAULT UNSEALED\n" + message;
}
```

```csharp
private const string Salt = "GLA::vault::key::v1::stars=";

public static byte[] DeriveKey(int stars) =>
    SHA256.HashData(Encoding.UTF8.GetBytes(Salt + stars.ToString(CultureInfo.InvariantCulture)));

public static byte[] Xor(byte[] data, byte[] key)
{
    var output = new byte[data.Length];
    for (int i = 0; i < data.Length; i++)
        output[i] = (byte)(data[i] ^ key[i % key.Length]);
    return output;
}
```

## 5. The actual bug

At a glance this looks like "get 6+ stars, vault opens, done." But look at the key
derivation: it hashes `Salt + player.WantedStars` — using whatever your **current**
star count is, not the constant `6`. Meanwhile the gate check is only `< 6` (i.e.
"6 or more passes"), not `== 6`.

So the SHA-256-derived XOR key only matches the key originally used to seal
`SealedBlob` when your star count is **exactly 6**. Any player who naturally
accumulates stars past 6 while playing gets "VAULT UNSEALED" — followed by garbage
bytes instead of a flag. That mismatch between the gate check and the value used
downstream is the whole trick, and almost certainly the joke behind the room's
"nobody's ever managed to open it" flavor text.

## 6. Getting the flag without playing the game

Since the exact algorithm and the real `SealedBlob` bytes are both sitting in the DLL,
there's no need to fight cops in-game to land on exactly 6 stars before it changes.
`PlayerState` and `SafehouseVault` both just extend `System.Object` (not
`Godot.Node`), so they can be instantiated and called directly via reflection —
no Godot engine required.

**`Program.cs`:**

```csharp
using System;
using System.Reflection;

var asm = Assembly.LoadFrom("GrandLarcenyAuto.dll");
var playerStateType = asm.GetType("GrandLarcenyAuto.PlayerState")!;
var vaultType       = asm.GetType("GrandLarcenyAuto.SafehouseVault")!;

var player = Activator.CreateInstance(playerStateType)!;
var wantedStarsProp = playerStateType.GetProperty("WantedStars")!;

foreach (var stars in new[] { 0, 5, 6, 7, 10 })
{
    wantedStarsProp.SetValue(player, stars);
    var vault = Activator.CreateInstance(vaultType, player)!;
    var result = vaultType.GetMethod("TryOpen")!.Invoke(vault, null);
    Console.WriteLine($"stars={stars} => {result}");
}
```

Build and run:

```bash
dotnet new console -o runner
cp GrandLarcenyAuto.dll GodotSharp.dll runner/
cd runner

# offline sandbox needs an empty NuGet.Config, otherwise `dotnet run`
# tries (and fails) to restore packages it doesn't actually need:
cat > NuGet.Config << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
  </packageSources>
</configuration>
EOF

dotnet run
```

**Output:**

```
stars=0  => The vault stays shut. ... (You need SIX stars. Good luck.)
stars=5  => The vault stays shut. ... (You need SIX stars. Good luck.)
stars=6  => VAULT UNSEALED
            THM{█████████████████████████}
stars=7  => VAULT UNSEALED
            <garbage bytes>
stars=10 => VAULT UNSEALED
            <garbage bytes>
```

Exactly 6 stars — and only exactly 6 — produces a clean decryption. Every other value
either fails the gate or unseals into noise, which confirms the exact-match theory.

> **Flag redacted** — this repo is a public writeup for an active room. Run the
> harness above against your own copy of the challenge files to get your instance's
> flag.

## Takeaways

- **Check the `.pck` size first** on any Godot challenge. If it's tiny, the logic is
  in a C# (or GDScript) file somewhere, and the shipped engine assets are a red
  herring.
- **`monodis`** is a fine substitute for a "real" .NET decompiler when dnSpy/ILSpy
  aren't available — you just read raw IL instead of pretty C#.
- **Control-flow flattening looks scarier than it is.** Stop trying to read it
  top-to-bottom; trace what value the method actually returns and the real logic
  falls out fast.
- **The core bug is a classic pattern:** the gate check (`>= 6`) and the value used
  downstream for crypto (`== 6` implicitly, via exact-match key derivation) aren't
  the same guarantee. This shows up in real auth/crypto bugs too, not just CTF rooms.
- **You don't need the actual game running** once you understand the algorithm —
  driving the compiled code directly via reflection is faster and more reliable than
  trying to reproduce exact in-game state.

## Tools used

- `strings`
- `mono-utils` (`monodis`)
- .NET 8 SDK (`dotnet new console`, reflection harness)

---

*Writeup for personal portfolio / TryHackMe practice — solved via static analysis,
no Windows VM used.*
