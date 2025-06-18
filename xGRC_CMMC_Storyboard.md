# xGRC/CMMC Advisor Compensation & Elevation Planning App

This storyboard outlines slides for a Lovely.ai deck describing the features and workflows of the proposed application.

---

## Slide 1: Application Vision

**Title:**
xGRC/CMMC Advisor Compensation & Elevation Planning App

**Subtitle:**
A unified dashboard for compensation modeling, advisor growth, and team planning

**Content:**
This application empowers leadership and advisors at Shellproof to transparently model, simulate, and track GRC/CMMC compensation, performance, and promotion eligibility—driving clarity, fairness, and accountability.

**Visual:**
App dashboard wireframe (bonus accrual, comp summary, advisor status)

---

## Slide 2: User Types & Navigation

**Title:**
Who Uses the App?

**Content:**
- **GRC Advisors**: Enter personal portfolio and credentials, track bonus eligibility and elevation status
- **Management/Admin**: Model compensation scenarios, monitor advisor pipeline, align compensation to business growth

**Navigation:**
- Home Dashboard
- Compensation Simulator
- Elevation Plan Tracker
- Multi-Year Planner
- (Admin) Team and Scenario Analysis

**Visual:**
Sidebar navigation mockup

---

## Slide 3: Core Features Overview

**Title:**
Core Features

**Content:**
1. **Compensation Simulator**
   - Enter advisor profile (salary, clients, MRR, certifications, tenure)
   - Auto-calculate bonus, total comp, and W-2 multiple
   - Bonus accrual dashboard shows "locked" bonuses awaiting eligibility
2. **Elevation Plan Workflow**
   - Track progress through 12-month provisional period
   - Checklist for client count, certification, client satisfaction, and internal quality
   - Decision logic: promotion, mentorship, or reversion
3. **Multi-Year Planning**
   - Forecast compensation, bonuses, and W-2 multiples over 5 years
   - Link annual recurring revenue (ARR) to sales forecasts
   - Sensitivity charts for pay-for-performance modeling
4. **Admin Panel**
   - Team-wide dashboard for headcount, comp pools, at-risk advisors, and scenario toggling

**Visual:**
Four tiles with icons summarizing each feature

---

## Slide 4: Compensation Simulator Flow

**Title:**
Compensation Simulator

**Content:**
Inputs include salary, client count, MRR, ARR, certifications, and months as primary on each account. Outputs show target ARR, multiple bonus types, total compensation, and W-2 multiple.

**Bonus Structure Logic:**
- <90% of target ARR: no bonus
- 90–99%: prorated bonus
- 100%: full bonus
- 110–119%: 1.25× multiplier
- 120%+: 1.5× multiplier
- 3-Month Rule: bonuses accrue but only pay out after 3 months as primary on the account

**Visual:**
Form UI, dynamic payout calculation, and a "locked bonus" widget showing accrued but not yet eligible bonuses

---

## Slide 5: Elevation Plan Workflow

**Title:**
Elevation Plan: Provisional to Official Promotion

**Content:**
Criteria include maintaining 6+ accounts for 12 months, required certifications, high client satisfaction, and internal quality scores. Annual review outcomes lead to official title and salary, mentorship extension, or reversion.

**Visual:**
Checklist with timeline and outcome cards

---

## Slide 6: Multi-Year & Sensitivity Modeling

**Title:**
Scenario Modeling & Multi-Year Planning

**Content:**
Set assumptions for ARR growth, salary increases, and new certifications over 5 years. View projected compensation, bonus pools, W-2 multiples, and advisor headcount linked to sales forecasts. Sensitivity charts illustrate how ARR changes affect payouts.

**Visual:**
Line chart for comp vs ARR and table for 5-year projections

---

## Slide 7: Bonus Accrual & Eligibility Dashboard

**Title:**
Bonus Accrual Dashboard

**Content:**
Track "unlocked" bonuses payable now and "locked" bonuses awaiting tenure or other requirements. Advisors receive notifications when a locked bonus becomes eligible.

**Visual:**
Accrual meter or progress bar with sample notification

---

## Slide 8: Admin & Team Dashboard

**Title:**
Admin Controls & Team Analytics

**Content:**
Model compensation and ARR growth scenarios, track advisor pipeline, run what-if analyses for hiring, and integrate with CRM for forecast-driven planning.

**Visual:**
Team summary dashboard with traffic light status and scenario toggles

---

## Slide 9: Key Rules and Business Logic

**Title:**
Key Rules

**Content:**
- Revenue bonus only pays after 3 months as primary on account
- Renewal bonus requires advisor to hold client at least 3 months prior to renewal
- Satisfaction and quality bonuses depend on thresholds (NPS ≥ 8, CSAT ≥ 90%)
- Annual review for provisional promotion requires meeting all criteria for title and salary to become official

**Visual:**
Callout boxes highlighting each rule

---

## Slide 10: Implementation & Next Steps

**Title:**
Implementation Roadmap

**Content:**
Build a prototype in React (or a preferred stack), embed spreadsheet logic into the backend, connect to CRM or sales tools for forecast-driven planning, and roll out to advisors and managers for real-time review.

**Visual:**
Stepwise roadmap graphic

---

## Notes for Lovely.ai

Use clean, modern visuals emphasizing dashboards, calculators, and charts. Highlight "locked" bonus widgets with color and animation. Include tooltips for rules and requirements and present the elevation workflow with a clear timeline.

