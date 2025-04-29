<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Nexovate Hub - Reliable Communication Solutions</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', sans-serif; background: #f2f6fc; color: #222; }
    header {
      background: linear-gradient(90deg, #007bff, #5fa8ff);
      color: #fff;
      padding: 20px 40px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: 0 2px 6px rgba(0,0,0,0.2);
    }
    nav a {
      color: #ccc;
      margin-left: 20px;
      text-decoration: none;
      font-weight: 600;
      transition: all 0.3s ease;
    }
    nav a:hover { color: #fff; text-decoration: underline; }

    .hero, .features, .auth-section, .dashboard-preview {
      padding: 60px 20px;
      text-align: center;
    }

    .hero-img {
      max-width: 100%;
      height: auto;
      border-radius: 16px;
      margin-top: 30px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    }

    .auth-box {
      background: #ffffff;
      padding: 40px;
      margin: auto;
      max-width: 400px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.1);
      border-radius: 12px;
    }

    .auth-box h2 {
      margin-bottom: 20px;
      color: #333;
    }

    .auth-box input {
      width: 100%;
      padding: 14px;
      margin-bottom: 20px;
      border: 1px solid #ccc;
      border-radius: 8px;
    }

    .auth-box button {
      width: 100%;
      background: linear-gradient(90deg, #007bff, #5fa8ff);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 8px;
      cursor: pointer;
      font-weight: bold;
    }

    .auth-box button:hover {
      background: linear-gradient(90deg, #005dc1, #4a91d7);
    }

    .dashboard-preview {
      background: #ffffff;
      border-top: 1px solid #ddd;
    }

    .dashboard-preview h2 {
      margin-bottom: 20px;
    }

    .dashboard-grid {
      display: flex;
      justify-content: center;
      gap: 40px;
      flex-wrap: wrap;
    }

    .card {
      background: #f9fafb;
      border: 1px solid #ccc;
      padding: 30px;
      border-radius: 10px;
      width: 250px;
      text-align: center;
      box-shadow: 0 2px 6px rgba(0,0,0,0.1);
      transition: all 0.3s ease;
    }

    .card:hover {
      background: #f1f5f9;
      box-shadow: 0 4px 16px rgba(0,0,0,0.1);
    }

    footer {
      text-align: center;
      padding: 30px;
      font-size: 14px;
      color: #666;
      background: #0b0f19;
      color: #ccc;
    }

    .footer-contact {
      margin-top: 10px;
      font-size: 15px;
      line-height: 1.8;
    }

    .footer-contact a {
      color: #5fa8ff;
      text-decoration: none;
    }

    .footer-contact a:hover {
      text-decoration: underline;
    }

    .twilio-link {
      margin-top: 25px;
      display: inline-block;
      font-size: 16px;
      color: #007bff;
      text-decoration: none;
    }

    .twilio-link:hover {
      text-decoration: underline;
    }

    .button-group {
      margin-top: 20px;
    }

    .button-group a {
      display: inline-block;
      background: linear-gradient(90deg, #28a745, #34d399);
      color: #fff;
      padding: 12px 20px;
      margin: 10px;
      border-radius: 8px;
      text-decoration: none;
      font-weight: 600;
      transition: background-color 0.3s ease;
    }

    .button-group a:hover {
      background: linear-gradient(90deg, #1e7e34, #4e9f6b);
    }
  </style>
</head>
<body>
  <header>
    <h1 style="font-weight:800; font-size:24px">Nexovate Hub</h1>
    <nav>
      <a href="#signup">Sign Up</a>
      <a href="#dashboard">Dashboard</a>
      <a href="#contact">Contact</a>
    </nav>
  </header>

  <section class="hero">
    <h2 style="font-size: 32px; font-weight: 700; color: #333;">Modern Communication Infrastructure for Everyone ✨</h2>
    <p style="font-size: 18px; margin-top:10px; color: #555;">Send SMS, Make Voice Calls, Verify Users. Built for developers, designed for business.</p>
    <img src="https://images.unsplash.com/photo-1600794282054-c52a60be4006?crop=entropy&cs=tinysrgb&fit=max&ixid=MnwzNjQyOXwwfDF8c2VhcmNofDJ8fG1vZGVsJTIwcGhvbmUlMjB0YWRpbmd8ZW58MHx8fHwxNjE4MjMwMjQy&ixlib=rb-1.2.1&q=80&w=1080" alt="Model with Headset" class="hero-img">
    <div class="button-group">
      <a href="#signup">Create Account Now</a>
      <a href="https://www.twilio.com/try-twilio" target="_blank">Try Twilio</a>
    </div>
  </section>

  <section class="auth-section" id="signup">
    <div class="auth-box">
      <h2>Create Your Nexovate Account 🔐</h2>
      <input type="text" placeholder="Full Name">
      <input type="email" placeholder="Email">
      <input type="password" placeholder="Password">
      <button>Create Account</button>
    </div>
  </section>

  <section class="dashboard-preview" id="dashboard">
    <h2>Dashboard Preview 📊</h2>
    <div class="dashboard-grid">
      <div class="card">
        <h3>Account Balance</h3>
        <p>$25.00</p>
      </div>
      <div class="card">
        <h3>Your API Key</h3>
        <p>api_nxv_124893</p>
      </div>
      <div class="card">
        <h3>Phone Number Purchase</h3>
        <button>Buy Number</button>
      </div>
    </div>
  </section>

  <footer id="contact">
    <div>&copy; 2025 Nexovate Hub. All rights reserved.</div>
    <div class="footer-contact">
      Contact us at: <a href="mailto:support@nexovatehub.online">support@nexovatehub.online</a><br>
      Support Phone: <a href="tel:+8801335438889">+8801335438889</a>
    </div>
  </footer>
</body>
</html>
