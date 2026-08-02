/// Byte-diff differential test for the alpha/beta-precompute patch to `Groth16Multi.mo`.
///
/// This is the test file referenced by Groth16Multi.mo's own doc comments
/// ("Correctness boundary (Groth16MultiTest.mo): ...") — it wasn't present in this repo
/// snapshot, so it's recreated here, pinned against the NEW 3-pair intermediate (not the old
/// 4-pair one) using values computed for real by `circuit/src/bin/oracle_pin_fixture.rs`
/// against the ACTUAL `circuit/wire_export.json` fixture — not synthetic data.
///
/// Comparison strategy: `TowerMont.mo`'s Fp12M coefficients are Montgomery-form Nats
/// (documented convention). `FpM.montMul(x, 1) == redc(x*1) == redc(x)`, which is exactly
/// the Montgomery-to-normal-form reduction — so every coefficient is converted back to
/// normal form with the existing public `FpM.montMul` (no source changes needed) before
/// comparing against arkworks' canonical (normal-form) values.
///
/// STATUS: written and pinned against a real, independently-computed oracle value, but NOT
/// executed in the sandbox that produced this patch — the JS-interpreted `moc` this project
/// falls back to when `dfx` is unavailable is documented (see `verify_test/main.mo`) as too
/// slow to finish even the OLD 4-pair pairing (killed after 17+ minutes); this NEW path is
/// ~19% cheaper in the Miller loop but not enough to change that. Needs `dfx`/`pocket-ic`
/// (or a working compiled-wasm execution path) to actually run. That is the one remaining
/// honest gap in this patch's verification story.

import GW "./vendor/Groth16Wire";
import GM "./vendor/Groth16Multi";
import PP "./vendor/PairingProjective";
import PF "./vendor/PairingFinalExp";
import FpM "./vendor/FpMont";
import TM "./vendor/TowerMont";
import CJ "./vendor/CurveJac";
import Debug "mo:base/Debug";

module {

  // Real fixture, byte-identical to circuit/wire_export.json — copy-pasted, not retyped.
  let vkHex = "8e59621a41bfdf8c88f7b3ca587bcb7908f7816cdcbeee728d579f0e2d9c969c0f14a7458e7d644d5cba44ca727d9683b7d20f8bbbac635f5dc67bc30d53d733c4b6492aae0bceb893af08c860d82de74232cd296c2ade51d242b4f73ccab5c6194d92d2f8c3d54a56cac7740eb8567d26d80695aaa4fcc86b7a53cb63348453aa6b773bc8333f15b3322878f814eb7bb75329f662720b6f0d588153cbcbbd3c1ad5aff56d736d480950c096ea0d3e831dde21a0515832e744984cb5ad15ce87144337deb52336ddd70b61b6578d50fc825f6ff59250134310bcc0d522107cd0f51d0e12546c345ed32a50209355b1668963a65cfbda06045b950f52b830fa264758e2dca730d7fac14aea685742b01470dd5293efaea7f86b50b2af56319e31027a517a3036ee9062a981bbc0a6f009a65e1ee34dac0be79cab6600c3272beb578126f8b83556c83345134f4c1d922507000000000000008e8f95331b20dc3cfdfdb766d3851d7e483bb1d9a6c42088dcaed70f1d5b52a1cc30e8a92ae18687d52875e1cf9328c7ad693aafb47be0fb62db63057f06e7ed629e88bf24ea23bb30bde701b43b29409ff64ff33463c89fe548895518ece719939403f78d9fba54171264eb6306da2d48eba37ddcb98d7cf74968e895fa4c36f5c547c2aaaa35d43e76018b2466ad84a36bed0819c8d6ae9570238037dedeb196e09f23b93d51a5e48d907a42c497aea7ba8fa8cd1d974c8dcb020fd0957dedadc3839161fe166b7971192d0939d663f76f0d8b0628c91d9acaf2b086489a1a39bcf2c66abf10e07b54b07ce8c9157e868e59c05c5190f90d1a362e5a999adbe41f77723c7bb215e7c535327b9371918019fd625699a82694697ceadeb948daace014abfde30f778634115cd6dbad17c601c5d54df14106d240d9f17be51bc84470b8bb25277679f3d622a8be443d2d";
  let proofHex = "ad0f3a226d9033373e6a67508b0f058d2f7a9d56693743e84b12380babcdfff4f2f49752e9144949d47ec5d3577bfb9e9251c3cb024edb981503712886570110b111d18c3529f05ef098d83fb3a27e9f4af046ff74cc69026ba313cadf4d2ad3011c6cdd936e578054abdb3145857bca887a35c8bf3ffc58f0e570f3e8841d31cdfbaea2ba9d4bf226970280a327eb9ea4814425e4bd6ed12043eefcccb5917b7dab21e7ab425b37158fcc37c518299ae51edb012d8a5f3397af19f2aca7e0ab";
  let inputsHex = "06000000000000000100000000000000000000000000000000000000000000000000000000000000a590f8f6b8e7f660c275bc808067e0dafe41363e0d688dc547afc6278327406b01000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000000000000000000000000000000000000000000060498468000000000000000000000000000000000000000000000000000000008d226c2b74f202f7ad3c9685072581b92deda899c9626c9caae46d0c0914d90a";
  let forgedInputsHex = "06000000000000000100000000000000000000000000000000000000000000000000000000000000a590f8f6b8e7f660c275bc808067e0dafe41363e0d688dc547afc6278327406b01000000000000000000000000000000000000000000000000000000000000002a00000000000000000000000000000000000000000000000000000000000000604984680000000000000000000000000000000000000000000000000000000015cd5b0700000000000000000000000000000000000000000000000000000000";

  // Pinned oracle values from `circuit/src/bin/oracle_pin_fixture.rs`, run for real against
  // the fixture above (ark-bls12-381 / ark-groth16 0.4, arkworks as the ground truth). All
  // Nats below are NORMAL form (not Montgomery), in TowerMont.mo's nested tower order.
  func targetCoeffs() : [Nat] = [
    632461197943021392941265170586089790950211028939151983365429511583612943297061795525253901787220600480560145630984,
    3879280237001207956656725111912597101145723872295078066645697378092905313347737924039546057637391427483164102094090,
    2493157049377599533739198270715514415380191970043966136882409014995119435863904528241766024211003699848446982667642,
    3941431726827915362402033997021482960803944730531446791931328891237296477379475858159048756461175414912713270405688,
    2388750453503758380985290939568654991830989304720501645298077931632275870654693232326869886109081821688892309500449,
    2240775460763022940367658712963466314319249574279615086050523015621241924488715409271675568066998201210712883785032,
    552182653811158881062537810003240110587105529797528372106713820626045421654899640277688476136498237285470631208926,
    2189858689690897995843965596059076733467389613753893422309236126072060424677950942389879086389282148566096560961872,
    1963965341728689473148390091771947023018036253002383045721022788219003745814795980149339483687835140564405398966776,
    1533269904669598123437175179340279129816937711255618328403626457992152220125131934391599216504539926394439880976805,
    254991122372837527048756205012170315680831139074520542561692141023397701397120895141927590183531256489103892491312,
    3588342517749136824652233307393667636827372208073500915236416576078584953619411431780859678461442501322826225954221,
  ];
  // (VALID fixture's finalExp output is byte-identical to targetCoeffs() — the whole point
  // of the alpha/beta precompute is that a valid proof's 3-pair product collapses to exactly
  // this constant. So valid-case pinning is the same array; kept as one function to avoid
  // a 24-constant duplicate that's trivially out of sync.)
  func validOutCoeffs() : [Nat] = targetCoeffs();

  func forgedOutCoeffs() : [Nat] = [
    316214563988650900231538338267443458967042861284226565504055073231875760164903007778013512700072842022041020423915,
    2061895497643113807528586114664354805635661583757468336919658025012288100162363231349462938927271887995702066011080,
    3920542334796535897982080433796081271647360431151476247135414035906697596577258305546110986414240055085484143531044,
    1394765265835590832563862659265792925068452361484605943985273362697718757734439227469540506877937574475893926156787,
    2494261467157718764261365420838532100512218184034851060182253437863379637809948761077937898859690546527636665766965,
    1190495775969840683014455133921949942136071698483853515147832619062377776954889081106632909241598262888789894025120,
    2845411221937855747253218944847047403997962315802707560266766369912745400216168783144965569135703581330129629453955,
    2215520331421986674420703290597336383843754212978580003697316623099027378521955821348572531181552977198258638483471,
    3834954983424279221692729935308611998229262666526632820738207702071916439145405172653676666854053574585581104226089,
    2042862112908247576687041372369666313972666338565948779078205202561762618657143610330425701049917125262323832014498,
    2083919335075523376438066782826326242782688284334125775605644291021602319546088561931931709062580308079057308824624,
    620047686120160602279147824979806173356576580861789641149643201583637056097245652139073254527638657316928314260743,
  ];

  /// Flatten an Fp12M into 12 Nats in tower order, converting each Mont-form coefficient
  /// back to normal form via `FpM.montMul(x, 1) == redc(x)`.
  func flatten(f : TM.Fp12M) : [Nat] {
    let m = func(x : Nat) : Nat { FpM.montMul(x, 1) };
    [
      m(f.c0.c0.c0), m(f.c0.c0.c1),
      m(f.c0.c1.c0), m(f.c0.c1.c1),
      m(f.c0.c2.c0), m(f.c0.c2.c1),
      m(f.c1.c0.c0), m(f.c1.c0.c1),
      m(f.c1.c1.c0), m(f.c1.c1.c1),
      m(f.c1.c2.c0), m(f.c1.c2.c1),
    ];
  };

  func eq12(a : [Nat], b : [Nat]) : Bool {
    var i = 0;
    var ok = true;
    while (i < 12) { if (a[i] != b[i]) { ok := false }; i += 1 };
    ok
  };

  /// Raw 3-pair Miller product + final exp for a given (proofHex, inputsHex) pair, computed
  /// exactly the way `verifyReference`/`verifyWithFlat` do internally.
  func rawVerifyOutput(vk : GM.PreparedVk, proofHex : Text, inputsHex : Text) : ?[Nat] {
    switch (GW.hexToBytes(proofHex), GW.hexToBytes(inputsHex)) {
      case (?pBytes, ?iBytes) {
        switch (GW.parseProof(pBytes), GW.parseInputs(iBytes)) {
          case (?proof, ?inputs) {
            let vkx = CJ.vkX(vk.gammaAbc, inputs);
            let bPrep = PP.prepareG2(proof.b);
            let raw = GM.multiMillerRaw(vk, proof.a, bPrep, proof.c, vkx);
            ?flatten(PF.finalExponentiate(raw));
          };
          case _ { null };
        };
      };
      case _ { null };
    };
  };

  public func run() : Bool {
    switch (GW.parseAndPrepareVk(vkHex)) {
      case (null) { Debug.print("FAIL: vk parse"); false };
      case (?vk) {
        // 1. alphaBetaTarget matches the pinned oracle value (this is the whole precompute).
        let targetOk = eq12(flatten(vk.alphaBetaTarget), targetCoeffs());
        Debug.print("alphaBetaTarget matches oracle: " # debug_show (targetOk));

        // 2. Raw 3-pair intermediate, byte-diffed against the oracle — for BOTH the valid
        //    fixture (must equal targetCoeffs()/validOutCoeffs()) and the forged one (must
        //    equal forgedOutCoeffs(), which is deliberately NOT equal to the target).
        let validRawOk = switch (rawVerifyOutput(vk, proofHex, inputsHex)) {
          case (?out) { eq12(out, validOutCoeffs()) };
          case (null) { false };
        };
        let forgedRawOk = switch (rawVerifyOutput(vk, proofHex, forgedInputsHex)) {
          case (?out) { eq12(out, forgedOutCoeffs()) };
          case (null) { false };
        };
        Debug.print("valid raw intermediate matches oracle: " # debug_show (validRawOk));
        Debug.print("forged raw intermediate matches oracle: " # debug_show (forgedRawOk));

        // 3. Top-level boolean differential, the project's own README convention
        //    (ACCEPT valid / REJECT forged) — confirms the assembled verify() still behaves
        //    correctly end to end, not just its intermediate.
        let acceptValid = GW.verifyPrepared(vk, proofHex, inputsHex);
        let acceptForged = GW.verifyPrepared(vk, proofHex, forgedInputsHex);
        Debug.print("verifyPrepared(valid): " # acceptValid);
        Debug.print("verifyPrepared(forged): " # acceptForged);

        targetOk and validRawOk and forgedRawOk
          and acceptValid == "ACCEPT"
          and acceptForged != "ACCEPT";
      };
    };
  };
};
