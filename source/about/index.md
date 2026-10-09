---
title: About
date: 2022-06-08 22:07:20
categories: about
---

# Juhyun Song (송주현)

[@preview](https://github.com/juhyun167)

## Experience

- **Security Engineer, Samsung Semiconductor** (Sep 2026 - Present)
    - Automated program analysis for cybersecurity

- **Intern, Samsung Semiconductor** (Mar 2023 - Jun 2023)
    - ARM TrustZone security testing
    - Publication: DTA (IEEE Access)


## Education

- **M.S. in Electrical Engineering** (Sep 2024 - Aug 2026)
	- KAIST, Daejeon, Korea
    - Publications: CROSS-X (ACM CCS 2025), QueryHouse (ESORICS 2026)

- **B.S. in Computer Science** (Mar 2018 - Aug 2024)
	- Korea University, Seoul, Korea


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


## Honors and Awards

- **DEF CON CTF Finals** (2026)
    - 9th place (Team The Seoul Sauna Shogunate)

- **Midnight Sun CTF Finals** (2026)
    - 4th place (Team RubiyaLab Expeditions)

- **FIESTA: Financial Institutes' Event on Security Threat Analysis** (2023)
    - 3rd place award (Team xerophthalmia)

- **MIST Minister Prize** (2021)
    - Top 10 (Hall of Fame), KITRI Best of the Best (BoB), 9th cohort
    - Cybersecurity expert development program supported by Korea’s MSIT


## Vulnerability Disclosure

- **[CVE-2021-27965](https://nvd.nist.gov/vuln/detail/CVE-2021-27965) (collective work)**
    - Privilege escalation vulnerability in MSI Dragon Center

- **KVE-2020-1585, KVE-2020-1604 (collective work)**
    - Privilege escalation vulnerabilities (Reported to KISA bug bounty)

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
