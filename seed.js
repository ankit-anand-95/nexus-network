const db = require('./db');
const bcrypt = require('bcryptjs');

async function seed() {
  console.log('🌱 Seeding database...');

  // Users
  const users = [
    { name: 'Ankit Anand', email: 'ankit@example.com', password: 'password', headline: 'Senior Software Engineer | React, Node.js, AWS', location: 'Bengaluru, India', about: 'Passionate about building scalable products. 6+ years in full-stack dev.', current_position: 'Senior Engineer at Google' },
    { name: 'Priya Sharma', email: 'priya@example.com', password: 'password', headline: 'Product Manager | Ex-Amazon | IIM-A', location: 'Mumbai, India', about: 'Building products that matter. Ex-Amazon PM with 8 years experience.', current_position: 'Product Manager at Flipkart' },
    { name: 'Rahul Verma', email: 'rahul@example.com', password: 'password', headline: 'Data Scientist | ML Engineer | Python', location: 'Hyderabad, India', about: 'ML enthusiast working on NLP and recommendation systems.', current_position: 'Data Scientist at Microsoft' },
    { name: 'Sneha Patel', email: 'sneha@example.com', password: 'password', headline: 'UI/UX Designer | Figma | Design Systems', location: 'Pune, India', about: 'Crafting user-centric experiences for 5 years.', current_position: 'Senior Designer at Razorpay' },
    { name: 'Arjun Nair', email: 'arjun@example.com', password: 'password', headline: 'DevOps Engineer | Kubernetes | Docker | AWS', location: 'Chennai, India', about: 'Automating everything. DevOps practitioner with a passion for reliability.', current_position: 'DevOps Lead at Infosys' },
  ];

  const insertedIds = [];
  const stmt = db.prepare(`INSERT OR IGNORE INTO users (name, email, password, headline, location, about, current_position) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  for (const u of users) {
    const hash = await bcrypt.hash(u.password, 10);
    const info = stmt.run(u.name, u.email, hash, u.headline, u.location, u.about, u.current_position);
    insertedIds.push(info.lastInsertRowid || db.prepare(`SELECT id FROM users WHERE email=?`).get(u.email).id);
  }
  const [ankitId, priyaId, rahulId, snehaId, arjunId] = insertedIds;
  console.log('✅ Users created');

  // Experiences
  const expStmt = db.prepare(`INSERT OR IGNORE INTO experiences (user_id, company, role, start_date, end_date, is_current, description) VALUES (?, ?, ?, ?, ?, ?, ?)`);
  expStmt.run(ankitId, 'Google', 'Senior Software Engineer', '2021-06', '', 1, 'Working on Google Pay infrastructure. Led team of 6 engineers.');
  expStmt.run(ankitId, 'Paytm', 'Software Engineer', '2018-07', '2021-05', 0, 'Built payment gateway serving 10M+ transactions/day.');
  expStmt.run(priyaId, 'Flipkart', 'Product Manager', '2020-03', '', 1, 'Owning the seller growth product. Grew GMV by 40%.');
  expStmt.run(priyaId, 'Amazon', 'Associate PM', '2017-06', '2020-02', 0, 'Launched 3 new features for Amazon Fresh India.');
  expStmt.run(rahulId, 'Microsoft', 'Data Scientist', '2022-01', '', 1, 'Working on Azure AI recommendation systems.');
  expStmt.run(snehaId, 'Razorpay', 'Senior Designer', '2021-08', '', 1, 'Leading design for payments and checkout experience.');
  expStmt.run(arjunId, 'Infosys', 'DevOps Lead', '2019-04', '', 1, 'Managing cloud infrastructure for 50+ microservices.');
  console.log('✅ Experiences created');

  // Education
  const eduStmt = db.prepare(`INSERT OR IGNORE INTO education (user_id, school, degree, start_year, end_year) VALUES (?, ?, ?, ?, ?)`);
  eduStmt.run(ankitId, 'IIT Delhi', 'B.Tech Computer Science', 2014, 2018);
  eduStmt.run(priyaId, 'IIM Ahmedabad', 'MBA', 2015, 2017);
  eduStmt.run(priyaId, 'Delhi University', 'B.Com', 2012, 2015);
  eduStmt.run(rahulId, 'BITS Pilani', 'M.Tech Data Science', 2018, 2020);
  eduStmt.run(snehaId, 'NID Ahmedabad', 'B.Des Interaction Design', 2015, 2019);
  eduStmt.run(arjunId, 'VIT Vellore', 'B.Tech IT', 2015, 2019);
  console.log('✅ Education created');

  // Skills
  const skillStmt = db.prepare(`INSERT OR IGNORE INTO user_skills (user_id, name) VALUES (?, ?)`);
  [['React', 'Node.js', 'TypeScript', 'AWS', 'PostgreSQL', 'Redis']].forEach(skills => skills.forEach(s => skillStmt.run(ankitId, s)));
  [['Product Strategy', 'User Research', 'SQL', 'A/B Testing', 'Roadmapping']].forEach(skills => skills.forEach(s => skillStmt.run(priyaId, s)));
  [['Python', 'Machine Learning', 'TensorFlow', 'NLP', 'Spark', 'SQL']].forEach(skills => skills.forEach(s => skillStmt.run(rahulId, s)));
  [['Figma', 'Design Systems', 'Prototyping', 'User Testing', 'CSS']].forEach(skills => skills.forEach(s => skillStmt.run(snehaId, s)));
  [['Kubernetes', 'Docker', 'Terraform', 'AWS', 'CI/CD', 'Linux']].forEach(skills => skills.forEach(s => skillStmt.run(arjunId, s)));
  console.log('✅ Skills created');

  // Connections
  const connStmt = db.prepare(`INSERT OR IGNORE INTO connections (requester_id, addressee_id, status) VALUES (?, ?, 'accepted')`);
  connStmt.run(ankitId, priyaId);
  connStmt.run(ankitId, rahulId);
  connStmt.run(priyaId, snehaId);
  connStmt.run(rahulId, arjunId);
  db.prepare(`UPDATE users SET connections_count=4 WHERE id=?`).run(ankitId);
  db.prepare(`UPDATE users SET connections_count=3 WHERE id=?`).run(priyaId);
  db.prepare(`UPDATE users SET connections_count=2 WHERE id=?`).run(rahulId);
  db.prepare(`UPDATE users SET connections_count=2 WHERE id=?`).run(snehaId);
  db.prepare(`UPDATE users SET connections_count=2 WHERE id=?`).run(arjunId);
  console.log('✅ Connections created');

  // Posts
  const postStmt = db.prepare(`INSERT INTO posts (author_id, content, is_anonymous, is_poll, is_published, likes_count, comments_count) VALUES (?, ?, ?, ?, 1, ?, ?)`);
  postStmt.run(ankitId, `🚀 Just got promoted to Senior Engineer at Google!

It's been a long journey — from small-town Bihar to IIT Delhi to FAANG. Key lessons from 6 years in the industry:

1. Code quality > code quantity
2. Communication is a superpower
3. Mentorship matters — find yours early
4. Build in public, fail in private

Grateful to everyone who believed in me. What's your biggest career lesson? 💙`, 0, 0, 847, 43);

  postStmt.run(priyaId, `Unpopular PM opinion: Most roadmaps are just wishful thinking disguised as strategy.

Real product work is:
• Talking to 20 customers this week
• Saying NO to 15 feature requests
• Killing your darling feature that got 0 adoption
• Convincing engineers why boring infra matters

What's your unpopular PM take? 👇`, 0, 0, 1203, 89);

  postStmt.run(rahulId, `After 6 months of tuning, our recommendation model hit 94% precision in production! 🎯

Used a combination of collaborative filtering + content-based signals + real-time feature store.

The secret? Not the fancy algorithm — it was the data quality pipeline we built first.

Garbage in, garbage out. Always.`, 0, 0, 534, 27);

  // Anonymous post
  postStmt.run(ankitId, `My manager takes credit for everything I build and I don't know how to handle it anymore. Has anyone dealt with this? HR seems useless here.

Thinking of quitting but the pay is good. 😔`, 1, 0, 321, 156);

  // Poll post
  const pollInfo = db.prepare(`INSERT INTO posts (author_id, content, is_poll, is_published, likes_count) VALUES (?, ?, 1, 1, 0)`).run(priyaId, `What's the BIGGEST challenge in your current job? (Poll 👇)`);
  const pollId = pollInfo.lastInsertRowid;
  const pollOptStmt = db.prepare(`INSERT INTO poll_options (post_id, option_text, votes_count) VALUES (?, ?, ?)`);
  pollOptStmt.run(pollId, 'Bad management / micromanagement', 234);
  pollOptStmt.run(pollId, 'Low salary / no growth', 189);
  pollOptStmt.run(pollId, 'Poor work-life balance', 312);
  pollOptStmt.run(pollId, 'Boring / irrelevant work', 143);

  postStmt.run(snehaId, `Design hot take: 99% of developers think Figma is for making things look pretty.

Wrong. Figma is for:
→ Reducing ambiguity before a single line of code
→ Getting stakeholder alignment without 5 meetings
→ Documentation that doesn't go stale

Best ROI investment any eng team can make: hire a great designer. 🎨`, 0, 0, 678, 34);

  postStmt.run(arjunId, `We reduced our AWS bill by 60% in 3 months. Here's exactly how:

1. Right-sized 40% of EC2 instances (dev env running prod sizes 🤦)
2. Reserved instances for stable workloads
3. S3 lifecycle policies — moved old logs to Glacier
4. Killed 12 forgotten Load Balancers from 2019
5. Spot instances for batch jobs

Savings: ₹18 lakhs/year. Story at 11.`, 0, 0, 2341, 198);

  console.log('✅ Posts created');

  // Salary entries
  const salStmt = db.prepare(`INSERT INTO salary_entries (user_id, company, role, salary_lpa, experience_years, city, tech_stack, is_anonymous) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  salStmt.run(ankitId, 'Google', 'Senior Software Engineer', 65, 6, 'Bengaluru', 'Go, Python, GCP', 0);
  salStmt.run(priyaId, 'Flipkart', 'Product Manager', 42, 8, 'Bengaluru', 'SQL, Mixpanel', 1);
  salStmt.run(rahulId, 'Microsoft', 'Data Scientist', 38, 4, 'Hyderabad', 'Python, Azure ML, Spark', 0);
  salStmt.run(snehaId, 'Razorpay', 'Senior Designer', 28, 5, 'Bengaluru', 'Figma, Framer', 1);
  salStmt.run(arjunId, 'Infosys', 'DevOps Lead', 22, 7, 'Chennai', 'Kubernetes, Terraform, AWS', 0);
  salStmt.run(ankitId, 'Paytm', 'Software Engineer', 18, 3, 'Noida', 'React, Node.js, MySQL', 1);
  salStmt.run(priyaId, 'Amazon', 'Associate PM', 24, 3, 'Bengaluru', '', 1);
  salStmt.run(rahulId, 'Swiggy', 'ML Engineer', 32, 3, 'Bengaluru', 'Python, TensorFlow, Kafka', 1);
  salStmt.run(snehaId, 'Ola', 'UI Designer', 16, 2, 'Bengaluru', 'Figma, Sketch', 1);
  salStmt.run(arjunId, 'Wipro', 'SRE', 14, 2, 'Hyderabad', 'Linux, Docker', 1);
  console.log('✅ Salary entries created');

  // Company reviews
  const revStmt = db.prepare(`INSERT INTO company_reviews (user_id, company, overall_rating, title, pros, cons, work_life_balance, culture, salary_rating, growth, would_recommend, is_anonymous) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  revStmt.run(ankitId, 'Google', 5, 'Best company I have worked at', 'Brilliant colleagues, amazing food, learning opportunities everywhere, great pay', 'Slow promotion cycles, lots of process, can feel bureaucratic', 4, 5, 5, 4, 1, 0);
  revStmt.run(priyaId, 'Amazon', 4, 'High bar, high growth', 'Leadership principles actually work, fast-paced, great for learning', 'WLB is poor, PIP culture can be stressful, very competitive internally', 2, 3, 4, 5, 1, 1);
  revStmt.run(rahulId, 'Microsoft', 4, 'Stable and chill but can be slow', 'WLB is excellent, good pay, diverse teams, lots of benefits', 'Not as exciting as FAANG peers, internal politics', 5, 4, 4, 3, 1, 0);
  revStmt.run(snehaId, 'Razorpay', 4, 'Great startup energy, solid pay', 'Fast growth, excellent engineering culture, direct impact', 'Long hours during sprints, startup uncertainty', 3, 5, 4, 5, 1, 1);
  revStmt.run(arjunId, 'Infosys', 3, 'Good for freshers, stagnant later', 'Job security, good for learning basics, decent WLB', 'Hike cycles are slow, outdated tech stack, bench anxiety', 4, 3, 2, 2, 0, 1);
  revStmt.run(priyaId, 'Flipkart', 4, 'Meesho killer mode on 🚀', 'Product culture is top-notch, good pay, fast decisions', 'Political at senior levels, constant reorgs', 3, 4, 4, 4, 1, 1);
  console.log('✅ Company reviews created');

  // Expert profiles
  const expProfileStmt = db.prepare(`INSERT OR IGNORE INTO expert_profiles (user_id, bio, expertise, session_types, price_per_session, rating, rating_count, total_sessions) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  expProfileStmt.run(ankitId, 'Senior SWE at Google with 6 years of experience in distributed systems and frontend. FAANG interviewer.', JSON.stringify(['System Design', 'DSA', 'Frontend', 'Node.js', 'Career Guidance']), JSON.stringify(['Mock Interview', 'Code Review', 'Career Guidance', 'Resume Review']), 800, 4.9, 47, 53);
  expProfileStmt.run(priyaId, 'IIM-A MBA, 8 years in Product. Have done 100+ PM interviews. Can help you crack PM roles at top companies.', JSON.stringify(['Product Management', 'Product Strategy', 'PM Interviews', 'Career Switch']), JSON.stringify(['Mock Interview', 'Career Guidance', 'Resume Review']), 1000, 4.8, 62, 71);
  expProfileStmt.run(rahulId, 'Data Scientist at Microsoft. Can help with ML concepts, Python, SQL, and data science interviews.', JSON.stringify(['Machine Learning', 'Python', 'SQL', 'Statistics', 'Data Science Interviews']), JSON.stringify(['Mock Interview', 'Code Review', 'Career Guidance']), 600, 4.7, 28, 31);
  console.log('✅ Expert profiles created');

  // Messages
  const msgStmt = db.prepare(`INSERT INTO messages (sender_id, receiver_id, content, is_read) VALUES (?, ?, ?, ?)`);
  msgStmt.run(priyaId, ankitId, 'Hey Ankit! Saw your post about the promotion. Congrats! 🎉', 1);
  msgStmt.run(ankitId, priyaId, 'Thanks Priya! How are things at Flipkart?', 1);
  msgStmt.run(priyaId, ankitId, 'Going great! We just launched a new seller feature. Would love to pick your brain on some backend architecture questions sometime.', 0);
  msgStmt.run(rahulId, ankitId, 'Ankit, are you available for a quick call this week? Want to discuss a side project idea.', 0);
  console.log('✅ Messages created');

  // Jobs
  const jobStmt = db.prepare(`INSERT INTO jobs (poster_id, title, company, location, job_type, salary_range, description, requirements) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
  jobStmt.run(ankitId, 'Senior Frontend Engineer', 'Google', 'Bengaluru, India (Hybrid)', 'Full-time', '50-80 LPA', 'Join our Google Pay team to build financial products at scale. You will work on React-based frontend serving millions of users.', 'React, TypeScript, 4+ years, CS degree preferred');
  jobStmt.run(priyaId, 'Product Manager - Growth', 'Flipkart', 'Bengaluru, India', 'Full-time', '35-55 LPA', 'Own the seller growth product. Work directly with business and engineering to drive GMV growth.', 'MBA preferred, 3+ years PM, strong analytical skills');
  jobStmt.run(rahulId, 'ML Engineer', 'Microsoft', 'Hyderabad, India (Hybrid)', 'Full-time', '30-50 LPA', 'Build recommendation and personalisation systems for Azure AI. Work with petabyte-scale data.', 'Python, ML frameworks, 2+ years, Masters preferred');
  jobStmt.run(snehaId, 'UX Designer', 'Razorpay', 'Bengaluru, India', 'Full-time', '20-35 LPA', 'Design end-to-end checkout and payments experience. Own the design system.', 'Figma, 3+ years, fintech background a plus');
  jobStmt.run(arjunId, 'DevOps / Platform Engineer', 'Infosys', 'Remote', 'Full-time', '18-28 LPA', 'Build and maintain Kubernetes-based platform for enterprise clients. Own CI/CD pipelines.', 'Kubernetes, Docker, Terraform, AWS/GCP, 3+ years');
  jobStmt.run(ankitId, 'Backend Engineer - Intern', 'Google', 'Bengaluru, India', 'Internship', '1.5L/month stipend', '6-month internship on the Google Pay backend team. Work on real production code from day 1.', 'Python or Go, final year or recent grad, good DSA fundamentals');
  console.log('✅ Jobs created');

  console.log('\n✨ Database seeded successfully!');
  console.log('\n🔑 Login credentials:');
  console.log('   ankit@example.com / password  (has expert profile)');
  console.log('   priya@example.com / password  (has expert profile)');
  console.log('   rahul@example.com / password  (has expert profile)');
  console.log('   sneha@example.com / password');
  console.log('   arjun@example.com / password');
  console.log('\n▶  npm start  to launch the app at http://localhost:3000');
}

seed().catch(console.error);
