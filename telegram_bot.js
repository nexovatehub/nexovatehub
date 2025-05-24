
const TelegramBot = require('node-telegram-bot-api');
const twilio = require('twilio');

let bot = null;
const twilioClients = new Map();

function initializeBot() {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  
  if (!token) {
    console.log('টেলিগ্রাম বট টোকেন সেট করা হয়নি। অনুগ্রহ করে /token পেজে গিয়ে টোকেন সেট করুন।');
    return;
  }

  try {
    if (bot) {
      bot.stopPolling();
    }
    
    bot = new TelegramBot(token, {
      polling: {
        interval: 300,
        autoStart: true,
        params: {
          timeout: 10
        }
      }
    });

    bot.on('polling_error', (error) => {
      console.log('Polling error:', error.code);  // Log only the error code
      if (error.code === 'ETELEGRAM') {
        console.log('Invalid token or network issue');
      }
    });

    bot.on('error', (error) => {
      console.error('Bot error:', error.code);
    });

    bot.getMe().then(() => {
      console.log('✅ টেলিগ্রাম বট সফলভাবে চালু হয়েছে!');
      setupBotHandlers();
    }).catch((error) => {
      console.error('❌ টেলিগ্রাম বট টোকেন ভুল অথবা এক্সপায়ার্ড:', error.message);
    });

  } catch (error) {
    console.error('❌ টেলিগ্রাম বট চালু করতে সমস্যা:', error.message);
  }
}

function setupBotHandlers() {
  if (!bot) return;

  // Command handler for /start
  bot.onText(/\/start/, (msg) => {
    const chatId = msg.chat.id;
    const keyboard = {
      keyboard: [
        ['/balance 💰', '/numbers 📱', '/refresh 🔄'],
        ['/buy কিনুন 🛒', '/delete মুছুন ❌', '/search 🔍']
      ],
      resize_keyboard: true,
      one_time_keyboard: false
    };
    
    bot.sendMessage(chatId, 'স্বাগতম! টুইলিও API কন্ট্রোল করতে নিচের বাটনগুলি ব্যবহার করুন:', {
      reply_markup: keyboard
    });
  });

  // Handle keyboard button responses
  bot.on('message', (msg) => {
    const chatId = msg.chat.id;
    const text = msg.text;

    if (text === '/balance 💰') {
      handleBalance(msg);
    } else if (text === '/numbers 📱') {
      handleNumbers(msg);
    } else if (text === '/buy কিনুন 🛒') {
      bot.sendMessage(chatId, 'নাম্বার কিনতে কমান্ড দিন: /buy <number>');
    } else if (text === '/delete মুছুন ❌') {
      bot.sendMessage(chatId, 'নাম্বার মুছতে কমান্ড দিন: /delete <number>');
    } else if (text === '/refresh 🔄') {
      handleNumbers(msg);
    } else if (text === '/search 🔍') {
      bot.sendMessage(chatId, 'এরিয়া কোড সার্চ করতে কমান্ড দিন: /search <areacode>');
    }
  });

  // Add search command handler
  bot.onText(/\/search (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const client = twilioClients.get(chatId);
    const areaCode = match[1];
    
    if (!client) {
      return bot.sendMessage(chatId, '❌ আগে লগইন করুন।');
    }

    try {
      const searchParams = {
        areaCode,
        limit: 10,
        smsEnabled: true,
        voiceEnabled: true
      };

      const [usNumbers, caNumbers] = await Promise.all([
        client.availablePhoneNumbers('US').local.list(searchParams),
        client.availablePhoneNumbers('CA').local.list(searchParams)
      ]);

      const allNumbers = [...usNumbers, ...caNumbers];
      
      if (allNumbers.length === 0) {
        return bot.sendMessage(chatId, `❌ ${areaCode} এরিয়া কোডে কোন নাম্বার পাওয়া যায়নি`);
      }

      const numbersList = allNumbers.map(n => `📞 ${n.phoneNumber}`).join('\n');
      bot.sendMessage(chatId, `🔍 "${areaCode}" এরিয়া কোডের নাম্বারগুলি:\n${numbersList}`);
    } catch (error) {
      bot.sendMessage(chatId, '❌ সার্চে সমস্যা হয়েছে। আবার চেষ্টা করুন।');
    }
  });

  // Login command
  bot.onText(/\/login (.+) (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const accountSid = match[1];
    const authToken = match[2];

    try {
      const client = twilio(accountSid, authToken);
      const account = await client.api.accounts(accountSid).fetch();
      const balance = await client.balance.fetch();
      
      if (!account || !balance) {
        throw new Error('Failed to fetch account information');
      }

      twilioClients.set(chatId, client);
      
      const message = `✅ সফলভাবে লগইন হয়েছে!\n\n` +
        `Account Name: ${account.friendlyName || 'Not Set'}\n` +
        `অ্যাকাউন্ট তৈরির তারিখ: ${account.dateCreated ? new Date(account.dateCreated).toLocaleString('bn-BD') : 'Not Available'}\n` + 
        `Balance: $${balance.balance ? Math.abs(parseFloat(balance.balance)).toFixed(2) : '0.00'}\n` +
        `Account Status: ${account.status || 'Unknown'}\n` +
        `Account Type: ${account.type || 'Unknown'}\n` +
        `Billing Country: ${account.countryCode || 'Not Set'}`;
      
      bot.sendMessage(chatId, message);
    } catch (error) {
      bot.sendMessage(chatId, '❌ লগইন ব্যর্থ হয়েছে। Account SID এবং Auth Token চেক করুন।');
    }
  });

  // Balance command
  bot.onText(/\/balance/, async (msg) => {
    handleBalance(msg);
  });

  // Numbers command
  bot.onText(/\/numbers/, async (msg) => {
    handleNumbers(msg);
  });

  // Buy number command
  bot.onText(/\/buy (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const client = twilioClients.get(chatId);
    const phoneNumber = match[1];
    
    if (!client) {
      return bot.sendMessage(chatId, '❌ আগে লগইন করুন।');
    }

    try {
      const number = await client.incomingPhoneNumbers.create({phoneNumber});
      bot.sendMessage(chatId, `✅ নাম্বার কেনা সফল হয়েছে: ${number.phoneNumber}`);
    } catch (error) {
      bot.sendMessage(chatId, '❌ নাম্বার কিনতে সমস্যা হয়েছে।');
    }
  });

  // Delete number command
  bot.onText(/\/delete (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    const client = twilioClients.get(chatId);
    const phoneNumber = match[1];
    
    if (!client) {
      return bot.sendMessage(chatId, '❌ আগে লগইন করুন।');
    }

    try {
      const numbers = await client.incomingPhoneNumbers.list({phoneNumber});
      if (numbers.length === 0) {
        return bot.sendMessage(chatId, '❌ এই নাম্বারটি পাওয়া যায়নি।');
      }
      
      await client.incomingPhoneNumbers(numbers[0].sid).remove();
      bot.sendMessage(chatId, `✅ নাম্বার ডিলিট করা হয়েছে: ${phoneNumber}`);
    } catch (error) {
      bot.sendMessage(chatId, '❌ নাম্বার ডিলিট করতে সমস্যা হয়েছে।');
    }
  });
}

async function handleBalance(msg) {
  const chatId = msg.chat.id;
  const client = twilioClients.get(chatId);
  
  if (!client) {
    return bot.sendMessage(chatId, '❌ আগে লগইন করুন।');
  }

  try {
    const balance = await client.balance.fetch();
    bot.sendMessage(chatId, `💰 বর্তমান ব্যালেন্স: $${Math.abs(balance.balance)}`);
  } catch (error) {
    bot.sendMessage(chatId, '❌ ব্যালেন্স লোড করতে সমস্যা হয়েছে।');
  }
}

async function handleNumbers(msg) {
  const chatId = msg.chat.id;
  const client = twilioClients.get(chatId);
  
  if (!client) {
    return bot.sendMessage(chatId, '❌ আগে লগইন করুন।');
  }

  try {
    const numbers = await client.incomingPhoneNumbers.list();
    if (numbers.length === 0) {
      return bot.sendMessage(chatId, '❌ কোন নাম্বার নেই।');
    }
    
    const numbersList = numbers.map(n => `📞 ${n.phoneNumber}`).join('\n');
    bot.sendMessage(chatId, `আপনার নাম্বারগুলি:\n${numbersList}`);
  } catch (error) {
    bot.sendMessage(chatId, '❌ নাম্বার লোড করতে সমস্যা হয়েছে।');
  }
}

// Function to broadcast number updates to all logged-in users
async function broadcastNumberUpdate(numbers, type = 'update', searchQuery = '') {
  if (!bot) {
    console.log('Telegram bot not initialized');
    return;
  }

  try {
    for (const [chatId, client] of twilioClients.entries()) {
      let message = '';
      if (type === 'refresh') {
        message = '🔄 নাম্বার লিস্ট রিফ্রেশ করা হয়েছে:\n';
      } else if (type === 'search') {
        message = `🔍 "${searchQuery}" এর জন্য সার্চ রেজাল্ট:\n`;
      } else {
        message = '📱 নাম্বার আপডেট:\n';
      }
      
      if (!numbers || numbers.length === 0) {
        message += 'কোন নাম্বার পাওয়া যায়নি';
      } else {
        message += numbers.map(n => `📞 ${n.phoneNumber || n.friendly_name || n}`).join('\n');
      }
      
      await bot.sendMessage(chatId, message);
    }
  } catch (error) {
    console.error('Error broadcasting number update:', error);
  }
}

initializeBot();

module.exports = {
  initializeBot,
  getBot: () => bot
};
