# DMCA Takedown / Anti-Circumvention Notice - TEMPLATE

> Fillable template used by `tools/dmca_packet.py`, which substitutes the `{{...}}` fields from a
> leaked-token attribution. **Have counsel review before sending.** The technical attribution names
> the buyer; the legal notice is what a host/registrar acts on. Elements track 17 U.S.C. § 512(c)(3)
> (takedown) and reference § 1201 (anti-circumvention), which is the actual lever for a licence crack.

---

To: {{host_or_registrar}} (designated DMCA agent)
From: {{rightsholder_name}}, {{rightsholder_contact}}
Date: {{notice_date}}
Re: Unauthorized distribution / circumvention of netplex. - {{infringing_url}}

1. **Copyrighted work.** The netplex. platform software and its licensed distribution, © {{rightsholder_name}}.

2. **Infringing material & location.** {{infringing_url}} hosts an unauthorized copy of, or a
   circumvention of the licence-verification measures in, the netplex. software.

3. **Attribution (technical basis).** The material carries a cryptographically-signed licence token
   attributable to our records:
   - buyer_id: **{{buyer_id}}**
   - license_id: **{{license_id}}**
   - signing key_id: **{{key_id}}** - signature verified: **{{signature_verified}}**
   - tier: {{tier}} · issued: {{issued_at}}
   This licence was issued to the above account under our EULA, which prohibits redistribution and
   circumvention (§ Anti-Circumvention). Revocation of this license_id has been issued via CRL.

4. **Good-faith statement.** I have a good-faith belief that the use of the material described above
   is not authorized by the copyright owner, its agent, or the law.

5. **Accuracy / authority (under penalty of perjury).** The information in this notice is accurate,
   and I am authorized to act on behalf of the owner of the exclusive right allegedly infringed.

6. **Anti-circumvention (17 U.S.C. § 1201).** The material also circumvents a technological measure
   that effectively controls access to the work (the licence-verification / entitlement system);
   distribution of such a circumvention is independently prohibited.

Signature: {{rightsholder_name}}
Contact: {{rightsholder_contact}}

---
*Generated {{notice_date}} by netplex-support/tools/dmca_packet.py from case {{case_id}}. Not legal
advice - review with counsel before sending.*
