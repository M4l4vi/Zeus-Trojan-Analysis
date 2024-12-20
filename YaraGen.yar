/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2024-12-16
   Identifier: Malicious_Findings
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule _home_kali_Desktop_Malicious_Findings_ihah {
   meta:
      description = "Malicious_Findings - file ihah.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-12-16"
      hash1 = "3b39bfc8c57c36b359d48506f6fada498407af5fb8cc9775e9aa4bd35c064470"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "AAA8AAAAAAAA" ascii /* base64 encoded string '  <      ' */
      $s3 = "  <description>Kea i l hiywildy ow</description>" fullword ascii
      $s4 = "      processorArchitecture=\"*\"" fullword ascii
      $s5 = "          processorArchitecture=\"X86\"" fullword ascii
      $s6 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s7 = "          version=\"6.0.0.0\"" fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "IIIJIIVIII" fullword ascii
      $s10 = "BBBBBBBBHBBBBBBBB" fullword ascii
      $s11 = "JJJJJJJJJJHJJJJJ" fullword ascii
      $s12 = "IIIVIIBI" fullword ascii
      $s13 = "JJFJJJJJ" fullword ascii
      $s14 = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" fullword ascii
      $s15 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii
      $s16 = "Ynagzakoykfeziucbye" fullword wide
      $s17 = "Vuupfaopescoydba" fullword wide
      $s18 = "Axumexupleopikoft" fullword wide
      $s19 = "Wyzesofooqbukyabykb" fullword wide
      $s20 = "Ziypewurkaucitamifg" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule b98679df6defbb3dc0e12463880c9dd7 {
   meta:
      description = "Malicious_Findings - file b98679df6defbb3dc0e12463880c9dd7.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-12-16"
      hash1 = "e1b672d536e62cf2988e1536807500a6b0ba8d0231c76f833a768375dc6aef8c"
   strings:
      $s1 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel>" fullword ascii
      $s2 = "  <description>Laatogly gel twatauxc g at</description>" fullword ascii
      $s3 = "      processorArchitecture=\"X86\"" fullword ascii
      $s4 = "          processorArchitecture=\"x86\"" fullword ascii
      $s5 = "          publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s6 = "xxxxxprp" fullword ascii
      $s7 = "          version=\"6.0.0.0\"" fullword ascii
      $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s9 = "DDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPA" ascii
      $s10 = "DDINGXXPADDINGPADDINGXXPADDINGPADD" fullword ascii
      $s11 = "          name=\"Microsoft.Windows.Common-Controls\"" fullword ascii
      $s12 = "Yldaepupreapagytek" fullword wide
      $s13 = "Iqkyliybotetafwa" fullword wide
      $s14 = "Wefietrenuyz" fullword wide
      $s15 = "Egewylvekeez" fullword wide
      $s16 = "Ufhokibiedqereo" fullword wide
      $s17 = "  <dependency>" fullword ascii
      $s18 = "  </trustInfo>" fullword ascii
      $s19 = "  </dependency>" fullword ascii
      $s20 = "nnxrypJS" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 500KB and
      8 of them
}

rule invoice_2318362983713_823931342io_pdf {
   meta:
      description = "Malicious_Findings - file invoice_2318362983713_823931342io.pdf.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-12-16"
      hash1 = "69e966e730557fde8fd84317cdef1ece00a8bb3470c0b58f3231e170168af169"
   strings:
      $s1 = "ejDmZKid5htD0UB[gZTHJVrLlTaTBBsBS18pEuDJBuMks{0H0zRNleRt2kh8S:QPqP/2v2JFYWjpubc,vQKhJvYCDZsyJKTWY,B6xyzRzzHY6Ezu44u6U6LOL[dhqVMn" ascii
      $s2 = "corect.com" fullword ascii
      $s3 = "KERNEL32.GetThreadPriority" fullword ascii
      $s4 = "USER32.GetShellWindow" fullword ascii
      $s5 = "KERNEL32.SystemTimeToFileTime" fullword ascii
      $s6 = "USER32.GetKeyNameTextA" fullword ascii
      $s7 = "KERNEL32.CreateIoCompletionPort" fullword ascii
      $s8 = "KERNEL32.GetWindowsDirectoryA" fullword ascii
      $s9 = "kqKDSPX2HCYOP/CYRnffTI[QZT{BN8Tafn,Jg2Ko[0X+i1oOknPp4ubEZniy2Q:OfQpxex4frsHQLes46ehHemEMxU9LPw{6VUKMC06pOw6cLW395ZdQdqxqDI6UQu7W" ascii
      $s10 = "KERNEL32.GetShortPathNameA" fullword ascii
      $s11 = "KERNEL32.GetStartupInfoW" fullword ascii
      $s12 = "9tc34LSgjT7ksJmvD1NxsNewhlynXj97U7O2OIsjnaNv0Vglp5FzexmnW7uVORnovysoxu0sKAIn0NYuxRcwu81fYFOEugVLBVJ+3jUAl/w2{hHZhK9leprOkc:ehsEO" ascii
      $s13 = "IKe397ub8CXtoFKc4rpl7t{DViecb2T7YM1yKaiMRmyCfs8Q:m[+PtURL3Myem6ZTR6kTSYjeph4xg1wlgrno+H0p81Wmn78yBOY76uEWgJRfJUWBsYj9UhYSyka,41W" ascii
      $s14 = "Dumpcotsavo" fullword ascii
      $s15 = "USER32.GetUpdateRgn" fullword ascii
      $s16 = "        <requestedExecutionLevel level='asInvoker' uiAccess=\"false\"/>" fullword ascii
      $s17 = "USER32.GetMonitorInfoW" fullword ascii
      $s18 = "gi4HzEwf0b9TQHjtEoOXk3TgcahTZe3sCGwEOg5iVBZz3WW7wkiNIMrnH0ZuSagxOTBaU93fuzD4BD7yiAU9MT6yUdT+fdoMjVpOOlOGZZVdXPV7cfpzMrUnxewB5eYr" ascii
      $s19 = "HqZswlyKCS+3sIljwEquEks[0gEBM9TOdumphQnrb:8ryevI39sm9kdzU6PUBpkzw1PrPPxcZ8KVgVkP9mY1DJLg/lvp1EStY6vXZUIvYinfzw5YJhaDY[JSTFpRK193" ascii
      $s20 = "jqiXzmPzIU8V590Xs8,5xbUM7YgXcpsjiizfRlhaQhH/pYXxG8LJqjhVskFt34KOlaJG9KCGjT,brQrWn/xuwTW3xm,CyP60F936QWqfEhEgN1gM830gOtrTb6hbP7ir" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and
      8 of them
}

rule _home_kali_Desktop_Malicious_Findings_vaelh {
   meta:
      description = "Malicious_Findings - file vaelh.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-12-16"
      hash1 = "a70aa9b1b476e59d41646a43ef553f671566a195ff04b5d2243fa363c562f6e0"
   strings:
      $s1 = "       <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" fullword ascii
      $s2 = "GetCompu" fullword ascii
      $s3 = " <requestedPrivileges>" fullword ascii
      $s4 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s5 = "8.5.0.3" fullword wide
      $s6 = "ttribu" fullword ascii
      $s7 = "Kaspersky" fullword wide /* Goodware String - occured 4 times */
      $s8 = "ForMultip%Objects<r" fullword ascii
      $s9 = "}Singc!7" fullword ascii
      $s10 = "8%D6U`c" fullword ascii
      $s11 = "terNameAFil" fullword ascii
      $s12 = "Ulmq+Y!n9K" fullword ascii
      $s13 = "bOauTh" fullword ascii
      $s14 = "$ToDlDnn{" fullword ascii
      $s15 = "SyUem`m(]" fullword ascii
      $s16 = "loseHnd" fullword ascii
      $s17 = " </trustInfo>" fullword ascii
      $s18 = " </security>" fullword ascii
      $s19 = "TzmE(NLK" fullword ascii
      $s20 = " <security>" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 300KB and
      8 of them
}

rule _home_kali_Desktop_Malicious_Findings_anaxu {
   meta:
      description = "Malicious_Findings - file anaxu.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2024-12-16"
      hash1 = "216a3cb0d30054825e1b5decb141001c7ff20962f88e79e69c5cc7bd8324496f"
   strings:
      $s1 = "6sHkp.exe" fullword wide
      $s2 = "CATSRV.DLL" fullword ascii
      $s3 = "        <requestedExecutionLevel" fullword ascii
      $s4 = "      processorArchitecture=\"X86\"" fullword ascii
      $s5 = "            processorArchitecture=\"X86\"" fullword ascii
      $s6 = "  <description>Miranda</description>" fullword ascii
      $s7 = "            publicKeyToken=\"6595b64144ccf1df\"" fullword ascii
      $s8 = "            version=\"1.0.0.0\"" fullword ascii
      $s9 = "      version=\"1.0.0.0\"" fullword ascii
      $s10 = "  </compatibility>" fullword ascii
      $s11 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" fullword ascii
      $s12 = "            version=\"6.0.0.0\"" fullword ascii
      $s13 = "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" fullword ascii
      $s14 = "            name=\"Microsoft.Windows.Common-Controls\"" fullword ascii
      $s15 = "60.40.109.60" fullword wide
      $s16 = "%P%P%@(P" fullword ascii
      $s17 = "  <dependency>" fullword ascii
      $s18 = "  </trustInfo>" fullword ascii
      $s19 = "  </dependency>" fullword ascii
      $s20 = "AMlNediHFq7ij5RTBi" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

