# ShadowXLab · VAPT Training Curriculum (sxl-cybercore.com)

Official web platform for the ShadowXLab 30-Day Beginner-to-Practitioner VAPT & Offensive Security Training Curriculum.

## Overview
- **30 Learning Days**: Step-by-step pathway from first principles to full engagement.
- **7 VAPT Stages**: Plan & Authorize, Reconnaissance, Scanning & Enumeration, Vulnerability Analysis, Controlled Validation, Impact Assessment, Reporting & Retesting.
- **Isolated Lab Pathway**: Local Dockerized practice with OWASP Juice Shop and Kali Linux workstation.
- **Evidence-Led Methodology**: Reproducible evidence collection and professional reporting.
- **Capstone Engagement**: NOVACORP simulated client assessment and portfolio defense.

## Local Development
Run locally with any static web server:
```bash
# Using Python
python -m http.server 3000

# Using npx serve
npx serve . -l 3000
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

## Deployment
Deploy using `deploy.bat` or directly via Cloudflare Pages:
```bash
npx wrangler pages deploy . --project-name=sxl-cybercore
```
Target Domain: `sxl-cybercore.com`
