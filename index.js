// --- 1. Import necessary modules ---
require('dotenv').config();
const { Client, GatewayIntentBits, Collection } = require('discord.js');
const axios = require('axios');
const express = require('express'); // NEW
const bodyParser = require('body-parser'); // NEW

// --- 2. Configuration from .env ---
const DISCORD_TOKEN = process.env.DISCORD_TOKEN;
const ROBLOX_COOKIE = process.env.ROBLOX_COOKIE;
const ROBLOX_GROUP_ID = parseInt(process.env.ROBLOX_GROUP_ID);
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET; // NEW: Secret key for security
const COMMAND_PREFIXES = ['!setrank', '!promote', '!demote'];
const REQUIRED_DISCORD_ROLE = 'Ranker';

// --- Cooldown Configuration ---
const COOLDOWN_SECONDS = 10; 
const PORT = process.env.PORT || 3000; // Railway provides the PORT environment variable

// --- 3. Initialize Discord Client & Cooldowns ---
const cooldowns = new Collection(); 
const client = new Client({ 
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent 
    ] 
});

// --- 4. Axios Session Setup (Roblox API Client) ---
const robloxClient = axios.create({
    baseURL: 'https://groups.roblox.com/v1',
    headers: {
        'Accept': 'application/json',
        'Cookie': `.ROBLOSECURITY=${ROBLOX_COOKIE}`
    },
    validateStatus: function (status) {
        return status >= 200 && status < 300 || status === 403; 
    }
});

// --- 5. Helper Functions (getXsrfToken, logAction remain the same) ---

async function getXsrfToken() {
    try {
        const tokenResponse = await robloxClient.post('https://accountinformation.roblox.com/v1/birthdate', {}, {
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (tokenResponse.headers && tokenResponse.headers['x-csrf-token']) {
             return tokenResponse.headers['x-csrf-token'];
        }
        return null; 
    } catch (error) {
        if (error.response && error.response.status === 403) {
            const csrfToken = error.response.headers['x-csrf-token'];
            if (csrfToken) {
                return csrfToken;
            }
        }
        return null;
    }
}

function logAction(source, status, username, currentRole, newRole, error = null) {
    if (!LOG_CHANNEL_ID || !client.isReady()) return; 

    // Find the Guild to find the Log Channel. We assume the bot is in at least one guild.
    const guild = client.guilds.cache.first();
    if (!guild) return; 

    const logChannel = guild.channels.cache.get(LOG_CHANNEL_ID);
    if (!logChannel) {
        console.error(`ERROR: Log channel with ID ${LOG_CHANNEL_ID} not found.`);
        return;
    }

    let logMessage = '';
    const executor = (source.author && source.author.tag) || 'Roblox Webhook';
    const sourceDetail = (source.channel && source.channel.name) || 'Game Server';
    const timestamp = new Date().toLocaleString();
    
    const oldRankName = currentRole ? currentRole.name : 'N/A';
    const oldRankNumber = currentRole ? currentRole.rank : 'N/A';
    const newRankName = newRole ? newRole.name : 'N/A';
    const newRankNumber = newRole ? newRole.rank : 'N/A';
    
    if (status === 'SUCCESS') {
        const action = oldRankNumber < newRankNumber ? '➡️ Promoted' : (oldRankNumber > newRankNumber ? '⬇️ Demoted' : '➡️ Set Rank');
        logMessage = 
            `**[✅ SUCCESS - RANK ACTION]**\n` +
            `*Source:* **${sourceDetail}**\n` +
            `*Executor:* ${executor}\n` +
            `*Target User:* **${username}**\n` +
            `*Action:* ${action} from **${oldRankNumber}** to **${newRankNumber}**\n` +
            `*Old Rank:* ${oldRankName} (Rank ${oldRankNumber})\n` +
            `*New Rank:* ${newRankName} (Rank ${newRankNumber})\n` +
            `*Time:* ${timestamp}`;
    } else if (status === 'FAILURE') {
        logMessage = 
            `**[🛑 FAILURE - RANK ACTION]**\n` +
            `*Source:* **${sourceDetail}**\n` +
            `*Executor:* ${executor}\n` +
            `*Target User:* **${username}**\n` +
            `*Attempted Rank:* ${newRankNumber}\n` +
            `*Error:* ${error}\n` +
            `*Current Rank:* ${oldRankName} (Rank ${oldRankNumber})\n` +
            `*Time:* ${timestamp}`;
    }

    if (logMessage) {
        logChannel.send(logMessage).catch(console.error);
    }
}

// --- 6. Roblox Ranker Logic (Unified for all commands) ---

async function processRobloxRankAction(source, username, rankValue, isAction) {
    let currentRole = null;
    let newRole = null;
    let targetRankNumber = isAction ? null : rankValue; 
    let actionType = isAction ? (rankValue === 1 ? 'promote' : 'demote') : 'set';
    let userId = null;
    let replyFunction = (msg) => { console.log(`[RESPONSE] ${msg.replace(/\*\*/g, '')}`); return { success: false, message: msg }; };
    
    // Determine where to send the response (Discord channel or Express HTTP response)
    if (source.reply) {
        // If source is a Discord message object
        replyFunction = (msg) => source.reply(msg);
    } else {
        // If source is an Express response object (from the webhook)
        replyFunction = (msg) => source.status(msg.includes('✅') ? 200 : 400).send({ success: msg.includes('✅'), message: msg });
    }

    try {
        // --- A. Get User ID ---
        const userLookupUrl = 'https://users.roblox.com/v1/usernames/users';
        const userResponse = await robloxClient.post(userLookupUrl, { usernames: [username], excludeBannedUsers: true });
        
        const userData = userResponse.data.data;
        if (!userData || userData.length === 0) {
            const errorMsg = `Roblox user **${username}** not found.`;
            logAction(source, 'FAILURE', username, null, null, errorMsg);
            return replyFunction(`🛑 **Error:** ${errorMsg}`);
        }
        userId = userData[0].id;

        // ... [B. Get Current Rank, C. Calculate Target Rank Number, D. Get All Roles] ... 
        // Logic remains the same: it calculates newRole and currentRole, and performs checks.
        
        const membershipUrl = `https://groups.roblox.com/v1/users/${userId}/groups/roles`;
        const membershipResponse = await robloxClient.get(membershipUrl);
        const groupMemberships = membershipResponse.data.data;
        const currentGroup = groupMemberships.find(g => g.group.id === ROBLOX_GROUP_ID);

        if (!currentGroup) {
            const errorMsg = `User **${username}** is not a member of the group.`;
            logAction(source, 'FAILURE', username, null, null, errorMsg);
            return replyFunction(`🛑 **Error:** ${errorMsg}`);
        }
        currentRole = currentGroup.role;

        if (isAction) {
            targetRankNumber = currentRole.rank + rankValue;
            
            if (targetRankNumber < 1) {
                const errorMsg = "Cannot demote further (user is at the lowest rank).";
                logAction(source, 'FAILURE', username, currentRole, null, errorMsg);
                return replyFunction(`🛑 **Limit Reached:** ${errorMsg}`);
            }
            if (targetRankNumber > 255) {
                const errorMsg = "Cannot promote further (user is at the highest rank).";
                logAction(source, 'FAILURE', username, currentRole, null, errorMsg);
                return replyFunction(`🛑 **Limit Reached:** ${errorMsg}`);
            }
        }
        
        const rolesUrl = `/groups/${ROBLOX_GROUP_ID}/roles`;
        const rolesResponse = await robloxClient.get(rolesUrl);
        const rolesData = rolesResponse.data.roles;

        newRole = rolesData.find(role => role.rank === targetRankNumber);

        if (!newRole) {
             const errorMsg = `Cannot find a role with rank number **${targetRankNumber}**.`;
             logAction(source, 'FAILURE', username, currentRole, null, errorMsg);
             return replyFunction(`🛑 **Error:** ${errorMsg}`);
        }

        if (newRole.rank === 255) {
             const errorMsg = "Cannot set a user's rank to Owner (Rank 255).";
             logAction(source, 'FAILURE', username, currentRole, null, errorMsg);
             return replyFunction("🛑 **Permission Error:** " + errorMsg);
        }

        if (currentRole.rank === newRole.rank) {
             const errorMsg = `User **${username}** is already at the target rank (**${newRole.name}**). No change was made.`;
             logAction(source, 'FAILURE', username, currentRole, newRole, errorMsg);
             return replyFunction(`🛑 **API Error:** ${errorMsg}`);
        }
        
        // --- E. Get CSRF Token & Execute Rank Change ---
        const csrfToken = await getXsrfToken();
        if (!csrfToken) {
             const errorMsg = "Could not obtain X-CSRF-TOKEN. Please check ROBLOX_COOKIE and group permissions.";
             logAction(source, 'FAILURE', username, currentRole, newRole, errorMsg);
             return replyFunction("🛑 **Authentication Error:** " + errorMsg);
        }

        const rankChangeUrl = `/groups/${ROBLOX_GROUP_ID}/users/${userId}`; 
        const rankChangePayload = { roleId: newRole.id }; 
        
        await robloxClient.patch(rankChangeUrl, rankChangePayload, {
            headers: { 'X-CSRF-TOKEN': csrfToken }
        });

        // G. Success Response
        const actionText = actionType.charAt(0).toUpperCase() + actionType.slice(1) + 'd';
        const successMsg = 
            `✅ **Success!** User **${username}** has been **${actionText}**.\n` +
            `**Old Rank:** ${currentRole.name} (Rank ${currentRole.rank})\n` +
            `**New Rank:** ${newRole.name} (Rank ${newRole.rank})`;
        
        logAction(source, 'SUCCESS', username, currentRole, newRole);
        return replyFunction(successMsg);

    } catch (error) {
        // --- FAILURE HANDLING ---
        let errorMessage = "An unknown network or API error occurred.";
        
        if (error.response) {
            if (error.response.data && error.response.data.errors) {
                 const apiError = error.response.data.errors[0];
                 const code = apiError.code;
                 const message = apiError.message;
                 errorMessage = `API Error (Code ${code}): ${message}`;
                 if (code === 10) {
                     errorMessage = "Insufficient permissions. The bot's Rank 250 account cannot rank this user.";
                 }
            } else if (error.response.status === 403) {
                errorMessage = "Authentication or Permission Error (403). Get a new, fresh ROBLOX_COOKIE.";
            } else if (error.response.status === 404) {
                errorMessage = "API Endpoint Not Found (404). Check the ROBLOX_GROUP_ID.";
            }
        } else if (error.request) {
            errorMessage = "Network Error: No response received from Roblox API.";
        } else {
             errorMessage = `Critical Error: ${error.message}`;
        }
        
        logAction(source, 'FAILURE', username, currentRole, null, errorMessage);
        return replyFunction(`🛑 **Roblox API Error:** ${errorMessage}`);
    }
}


// --- 8. Discord Listener (Same as before) ---

client.on('messageCreate', async (message) => {
    if (message.author.bot) return;

    const args = message.content.trim().split(/\s+/);
    const command = args[0].toLowerCase();
    
    if (!COMMAND_PREFIXES.includes(command)) return;

    // COOLDOWN LOGIC (omitted for brevity, assume it's here)
    // ... [Cooldown logic from previous working code] ...
    if (!cooldowns.has(command)) {
        cooldowns.set(command, new Collection());
    }

    const now = Date.now();
    const timestamps = cooldowns.get(command);
    const cooldownAmount = COOLDOWN_SECONDS * 1000;
    const userId = message.author.id;

    if (timestamps.has(userId)) {
        const expirationTime = timestamps.get(userId) + cooldownAmount;
        if (now < expirationTime) {
            const timeLeft = (expirationTime - now) / 1000;
            return message.reply(`⏳ Please wait **${timeLeft.toFixed(1)} more second(s)** before reusing the \`${command}\` command.`);
        }
    }
    
    timestamps.set(userId, now);
    setTimeout(() => timestamps.delete(userId), cooldownAmount);
    // END COOLDOWN LOGIC

    const requiredRole = message.guild.roles.cache.find(role => role.name === REQUIRED_DISCORD_ROLE);
    if (!requiredRole || !message.member.roles.cache.has(requiredRole.id)) {
        return message.reply(`🛑 **Permission Denied!** You must have the **${REQUIRED_DISCORD_ROLE}** role to use this command.`);
    }

    if (command === '!setrank') {
        if (args.length !== 3) {
            return message.reply("🛑 **Invalid Input:** Please use the format `!setrank <RobloxUsername> <RankNumber>`.");
        }
        const username = args[1];
        const targetRankNumber = parseInt(args[2]);

        if (isNaN(targetRankNumber) || targetRankNumber < 1 || targetRankNumber > 255) {
            return message.reply("🛑 **Invalid Rank:** The rank number must be a valid number between 1 and 255.");
        }
        await processRobloxRankAction(message, username, targetRankNumber, false);

    } else if (command === '!promote' || command === '!demote') {
        if (args.length !== 2) {
            return message.reply(`🛑 **Invalid Input:** Please use the format \`${command} <RobloxUsername>\`.`);
        }
        const username = args[1];
        const rankModifier = command === '!promote' ? 1 : -1;
        
        await processRobloxRankAction(message, username, rankModifier, true);
    }
});


// --- 9. Webhook Setup (NEW) ---
const app = express();
app.use(bodyParser.json());

app.post('/rank-webhook', async (req, res) => {
    const { secret, username, action, rank_number } = req.body;

    // 1. Secret Key Validation (Security Check)
    if (!secret || secret !== WEBHOOK_SECRET) {
        return res.status(401).send({ success: false, message: 'Invalid or missing webhook secret.' });
    }

    // 2. Input Validation
    if (!username || !action) {
        return res.status(400).send({ success: false, message: 'Missing username or action.' });
    }

    // 3. Command Mapping
    let rankValue, isAction;

    if (action === 'promote') {
        rankValue = 1;
        isAction = true;
    } else if (action === 'demote') {
        rankValue = -1;
        isAction = true;
    } else if (action === 'setrank' && rank_number !== undefined) {
        rankValue = parseInt(rank_number);
        isAction = false;
        if (isNaN(rankValue) || rankValue < 1 || rankValue > 255) {
            return res.status(400).send({ success: false, message: 'Invalid rank_number for setrank.' });
        }
    } else {
        return res.status(400).send({ success: false, message: 'Invalid action or missing rank_number for setrank.' });
    }

    // 4. Execute Rank Action (pass the Express response object as the source)
    await processRobloxRankAction(res, username, rankValue, isAction);
});


// --- 10. Start Server and Discord Bot ---

client.on('ready', () => {
    console.log(`🤖 Discord bot is ready!`);
    
    // Start the Express web server ONLY AFTER the Discord bot is ready
    app.listen(PORT, () => {
        console.log(`📡 Webhook server listening on port ${PORT}`);
    });
});

client.login(DISCORD_TOKEN);
