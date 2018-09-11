
## 1.0.2
- Add support for [SLIP-132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
    - yprv/zprv keys can now be imported
    - public.txt file includes both SLIP-132 and BIP-32 values where needed (segwit cases)
    - test cases added to match
- Can create Electrum skeleton wallet for Segwit Native and Segwit P2SH now.
    - caveat: the plugin is not ready yet for P2SH/Segwit, but Segwit native is fine
- Improvements in 'public.txt' output:
    - add SLIP-132 values where we can
    - correct names when used for Litecoin
- Improvements to backup and restore
    - can now restore cleartext backups (for devs only!)
    - fix "Unable to open ... /sd/backup.7z" error

## 1.0.1
- Touch sensitivity improvements: now less sensitive (by default) and a new setting can
  change that back to fast and sensitive, or select low sensitivity for noisy environments or
  personal preference.
- Remove respin feature (press 2) when showing seed words, and add confirm step
  to Cancel press. This misfeature was causing grief due to accidents during the
  high-stress seed word process.
- Improvement: show better what's happening during PIN attempt forced delay.
- Bugfix: possible lockup after entering an incorrect PIN code
- Bugfix: 'warm reset' inside Debug Functions didn't work properly.


## 1.0.0r2
- Initial release to public
