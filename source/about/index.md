---
title: About
date: 2022-06-08 22:07:20
categories: about
---

# Juhyun Song (송주현)

[@preview](https://github.com/juhyun167)


## Education

- **M.S. in Electrical Engineering** (Sep. 2024 - Aug. 2026)
    - Advisor: Insu Yun
	- KAIST, Daejeon, Korea

- **B.S. in Computer Science** (Mar. 2018 - Aug. 2024)
	- Korea University, Seoul, Korea


## Experience

- **Intern, Samsung Electronics** (Mar. 2023 - Jun. 2023)
    - Conducted TrustZone security research and published DTA in IEEE Access.

- **Cyber Operations Specialist, Republic of Korea Army** (Aug. 2021 - Feb. 2023)
    - Participated in CTF competitions with VII Maneuver Corps.

## Publications

### International Conference

- **QueryHouse: Cross-DBMS Differential Testing with LLM and Query Transpilation**
    - Seoyeon Oh, **Juhyun Song**, Jaemin Park, Kwanghee Lee, Minae Hyeon, Minji Kim, Sehyuk Ka, Gwangwun Jung, Brian Pak, and Insu Yun
    - European Symposium on Research in Computer Security (ESORICS) 2026 [<i class="fa-solid fa-globe"></i>](https://github.com/queryhouse-2037/QueryHouse.git)
- **CROSS-X: Generalized and Stable Cross-Cache Attack on the Linux Kernel**
    - Dong-ok Kim<span class="tooltip-wrapper"><i class="fa-solid fa-circle-info"></i><span class="tooltip-text">Equal Contribution</span></span>, **Juhyun Song<span class="tooltip-wrapper"><i class="fa-solid fa-circle-info"></i><span class="tooltip-text">Equal Contribution</span></span>**, and Insu Yun
    - ACM Conference on Computer and Communications Security (CCS) 2025 [<i class="fa-solid fa-globe"></i>](https://github.com/juhyun167/CROSS-X)

### International Journal

- **DTA: Run TrustZone TAs Outside the Secure World for Security Testing**
    - **Juhyun Song**, Eunji Jo, and Jaehyu Kim
    - IEEE Access, vol. 12, pp. 16715-16727, 2024 [<i class="fa-solid fa-globe"></i>](https://github.com/juhyun167/dta)


## Talks

- **Stabilizing Linux Cross-Cache Attacks**
    - .HACK Conference 2026, Seoul, Korea

- **Towards Comprehensive Fuzzing of TrustZone TAs**
    - .HACK Conference 2024, Seoul, Korea [<i class="fa-solid fa-file-pdf"></i>](/uploads/talks/dothack_2024.pdf)


## Projects

- **MacOS Application Security Assessment** (Mar. 2025 - Nov. 2025)
    - Applied an LLM-driven reverse-engineering workflow to security assessments of third-party macOS applications.
    - Received KIISC (한국정보보호학회) Research Excellence Award.

- **Relational DBMS Differential Testing** (Sep. 2024 - Dec. 2024)
    - Project lead for differential testing of SQL engines using LLM-driven mutation and cross-dialect transpilation.
    - Discovered 12 logic bugs and 16 undocumented behavioral inconsistencies across 5 DBMS. [<i class="fa-solid fa-globe"></i>](https://github.com/queryhouse-2037/QueryHouse/blob/main/docs/BUGLIST.md)

- **Windows Driver Security Assessment** (Sep. 2020 - Dec. 2020)
    - Co-designed a custom fuzzer and contributed to exploit development for Windows driver security testing.
    - Discovered 20 bugs, including exploitable 0-days (e.g., CVE-2021-27965). [<i class="fa-solid fa-globe"></i>](https://kronl.github.io/docs/)


## Honors and Awards

- **Midnight Sun CTF Finals** (2026)
    - 4th place (Team RubiyaLab Expeditions)

- **HACKSIUM BUSAN Hacking Competition** (2025)
    - 4th place award (Team 핵쉬움)

- **FIESTA: Financial Institutes' Event on Security Threat Analysis** (2023)
    - 3rd place award (Team xerophthalmia)

- **MIST Minister Prize** (2021)
    - Awarded to top 10 participants of KITRI Best of the Best 9th (10M KRW)


## Vulnerability Disclosure

- **[CVE-2021-27965](https://nvd.nist.gov/vuln/detail/CVE-2021-27965) (collective work)**
    - Privilege escalation vulnerability in MSI Dragon Center

- **KVE-2020-1585, KVE-2020-1604 (collective work)**
    - Privilege escalation vulnerabilities in gaming software and keyboard security solution (Reported to KISA bug bounty)

- **NBB-1705**
    - Stored XSS vulnerability in kin.naver.com (Reported to Naver bug bounty)


## Certifications

- **Craftsman Bartender** (2024)
    - National Certification, HRDK, Korea

<script>
// Tooltip touch support for Safari
document.addEventListener('DOMContentLoaded', function() {
  const tooltips = document.querySelectorAll('.tooltip-wrapper');

  tooltips.forEach(function(tooltip) {
    // Make tooltip focusable for keyboard and touch
    tooltip.setAttribute('tabindex', '0');

    // Handle touch events for mobile Safari
    tooltip.addEventListener('touchstart', function(e) {
      e.preventDefault();

      // Hide all other tooltips
      tooltips.forEach(function(t) {
        if (t !== tooltip) {
          t.classList.remove('tooltip-active');
        }
      });

      // Toggle current tooltip
      tooltip.classList.toggle('tooltip-active');
    }, { passive: false });
  });

  // Close tooltip when clicking outside
  document.addEventListener('touchstart', function(e) {
    if (!e.target.closest('.tooltip-wrapper')) {
      tooltips.forEach(function(t) {
        t.classList.remove('tooltip-active');
      });
    }
  });
});
</script>
