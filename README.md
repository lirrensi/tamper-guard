# 🛡️ TamperGuard - Your PC's Secret Agent Against Burglars & Curious Colleagues

*Because your laptop deserves better security than a "password123"*

## 🎯 What It Does (In Simple Terms)
TamperGuard is like having a security guard for your computer! When someone tries to guess your password wrong (3 times in a row while your PC is locked), it **SHUTS DOWN YOUR COMPUTER** 🔥

It's specifically designed to protect against:
- Random burglars trying to access your PC
- Curious colleagues who think you're "just" at your desk
- Unprepared attackers who want to get in through your screen lock

## 🚨 How It Works (The Magic Behind the Curtain)
1. **It watches your lock screen** like a hawk for failed login attempts
2. **Counts every wrong password** (up to your chosen limit)
3. **If it gets too many wrong tries**, it shuts down your PC before the attacker can try more!
4. **When you unlock successfully** or lock again, it resets the counter

## 🧪 Tested & Approved! 
✅ Windows 11 (25H02) - Real machine & VM  
✅ Works like a charm (though we're not saying it's *perfect* 😈)

## 🛠️ How to Use (It's Actually Pretty Easy!)
### Method 1: The Easy Way (Recommended)
- Run `run.bat` (it'll ask for admin privileges)
- Choose option 1 to register the guard

### Method 2: If the .bat doesn't work
```powershell
powershell -ExecutionPolicy Bypass -Command "& '.\TamperGuard.ps1'"
```

## ⚠️ Important Notes (Because We Care)
- **Not enterprise-grade** - It's for casual users who want extra peace of mind
- **Can be bypassed** - If someone has physical access and can boot into Safe Mode (use BitLocker!)
- **Works best with BitLocker** - Otherwise, they could just try over and over again
- **Not for coerced input** - If someone makes you type it, it's still game over

## 🎉 Test It Yourself! 
We've tested this on both real hardware and virtual machines, and it works like a charm! Try it out and see how much more secure your computer feels. Just remember - **be careful with your password, because if someone gets it right the first time, you're in trouble anyway!** 😈

## 💡 Pro Tip
Set it to 2 or 3 wrong attempts if you're very security-conscious, but remember - the more attempts you allow, the more time an attacker has to try!

**Made with ❤️ for people who want to keep their digital lives a little more private**