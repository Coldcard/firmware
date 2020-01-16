# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# hsm.py
#
# Unattended signing of transactions and messages, subject to a set of rules.
#
import stash, ustruct, tcc, ux, chains, sys, gc, uio, ujson, uos, utime
from sffile import SFFile
from utils import problem_file_line, cleanup_deriv_path
from pincodes import AE_LONG_SECRET_LEN
from stash import blank_object
from users import Users, MAX_NUMBER_USERS
from public_constants import MAX_USERNAME_LEN
from multisig import MultisigWallet

# where we save policy/config
POLICY_FNAME = '/flash/hsm-policy.json'

# number of digits in our "local confirmation" pin
LOCAL_PIN_LENGTH = 4

# max number of sats in the world: 21E6 * 1E8
MAX_SATS = const(2100000000000000)

def hsm_policy_available():
    # Is there an HSM policy ready to go? Offer the menu item then.
    try:
        uos.stat(POLICY_FNAME)
        return True
    except:
        return False

def pop_list(j, fld_name, cleanup_fcn=None):
    # returns either None or a list of items; raises if not a list (ie. single item)
    # return [] if not defined.
    v = j.pop(fld_name, None)
    if v:
        if not isinstance(v, list):
            raise ValueError("need a list for: " + fld_name)
        if cleanup_fcn:
            return [cleanup_fcn(i) for i in v]
        return v
    else:
        return []

def pop_int(j, fld_name, mn=0, mx=1000):
    # returns an int or None. Also range check.
    v = j.pop(fld_name, None)
    if v is None: return v
    assert int(v) == v, "%s: must be integer" % fld_name
    v = int(v)
    assert mn <= v <= mx, "%s: must in range: [%d..%d]" % (fld_name, mn, mx)
    return v

def pop_bool(j, fld_name, default=False):
    # return a bool, but accept 1/0 and True/False
    return bool(j.pop(fld_name, default))

def pop_string(j, fld_name, mn_len=0, mx_len=80):
    v = j.pop(fld_name, None)
    if v is None: return v
    assert isinstance(v, str), '%s: must be string' % fld_name
    assert mn_len <= len(v) <= mx_len, '%s: length must be %d..%d' % (fld_name, mn_len, mx_len)
    return v

def assert_empty_dict(j):
    extra = set(j.keys())
    if extra:
        raise ValueError("Unknown item: " + ', '.join(extra))

def cleanup_whitelist_value(s):
    # one element in a list of addresses or paths or descriptors?
    # - later matching is string-based, so just using basic syntax check here
    # - must be checksumed-base58 or bech32
    try:
        tcc.codecs.b58_decode(s)
        return s
    except: pass

    try:
        tcc.codecs.bech32_decode(s)
        return s
    except: pass

    raise ValueError('bad whitelist value: ' + s)

class ApprovalRule:
    # A rule which describes transactions we are okay with approving. It documents:
    # - whitelist: list/pattern of destination addresses allowed (or any)
    # - per_period: velocity limit in satoshis
    # - users: list of authorized users
    # - min_users: how many of those are needed to approve
    # - local_conf: local user must also confirm w/ code

    def __init__(self, j, idx):
        # read json dict provided

        def check_user(u):
            if not Users.valid_username(u):
                raise ValueError("Unknown user: %s" % u)
            return u

        self.index = idx+1
        self.per_period = pop_int(j, 'per_period', 0, MAX_SATS)
        self.max_amount = pop_int(j, 'max_amount', 0, MAX_SATS)
        self.users = pop_list(j, 'users', check_user)
        self.whitelist = pop_list(j, 'whitelist', cleanup_whitelist_value)
        self.min_users = pop_int(j, 'min_users', 0, len(self.users))
        self.local_conf = pop_bool(j, 'local_conf')
        self.wallet = pop_string(j, 'wallet', 1, 20)

        # usernames need to be correct and already known
        if self.min_users is None:
            self.min_users = len(self.users)
        assert self.min_users <= len(self.users), "need more users"

        # if specified, 'wallet' must be an existing multisig wallet's name
        if self.wallet and self.wallet != '1':
            names = [ms.name for ms in MultisigWallet.get_all()]
            assert self.wallet in names, "unknown MS wallet: "+self.wallet

        assert_empty_dict(j)

    @property
    def has_velocity(self):
        return self.per_period is not None

    def to_json(self):
        # remote users need to know what's happening, and we save this
        # cleaned up data
        flds = [ 'per_period', 'max_amount', 'users', 'min_users',
                    'local_conf', 'whitelist', 'wallet' ]
        return dict((f, getattr(self, f, None)) for f in flds)


    def to_text(self):
        # Text for human's to read and approve.
        chain = chains.current_chain()

        def render(n):
            return ' '.join(chain.render_value(n))

        if self.per_period:
            rv = 'Up to %s per period' % render(self.per_period)
            if self.max_amount:
                rv += ', and up to %s per txn' % render(self.max_amount)
        elif self.max_amount:
            rv = 'Up to %s per txn' % render(self.max_amount)
        else:
            rv = 'Any amount'

        if self.wallet == '1':
            rv += ' (non multisig)'
        elif self.wallet:
            rv += ' from multisig wallet "%s"' % self.wallet

        if self.users:
            rv += ' may be authorized by '
            if self.min_users == len(self.users):
                rv += 'all users'
            elif self.min_users == 1:
                rv += 'any one user'
            elif self.min_users:
                rv += 'at least %d users' % self.min_users
            rv += ' (%s)' % ', '.join(self.users)
        else:
            rv += ' will be approved'

        if self.whitelist:
            rv += ' provided it goes to: ' + ', '.join(self.whitelist)

        if self.local_conf:
            rv += ' if local user confirms'

        return rv

    def matches_transaction(self, psbt, users, total_out, dests):
        # Does this rule apply to this PSBT file? 
        if self.wallet:
            # rule limited to one wallet
            if psbt.active_multisig:
                # if multisig signing, might need to match specific wallet name
                assert self.wallet == psbt.active_multisig.name, 'wrong wallet'
            else:
                # non multisig, but does this rule apply to all wallets or single-singers
                assert self.wallet == '1', 'not multisig'

        if self.max_amount is not None:
            assert total_out <= self.max_amount, 'too much out'

        # check all destinations are in the whitelist
        if self.whitelist:
            diff = set(dests) - set(self.whitelist)
            assert not diff, "non-whitelisted dest: " + ', '.join(diff)

        return True

class HSMPolicy:
    # implements and enforces the HSM signing/activity/logging policy

    def load(self, j):
        # Decode json object provided: destructive
        # - attr name == json name if possible
        # - NOTE: always add to self.save()!
        # - raise errors and they will be shown to user

        # fail if we can't log it
        self.must_log = pop_bool(j, 'must_log')

        # don't fail on PSBT warnings
        self.warnings_ok = pop_bool(j, 'warnings_ok')

        # a list of paths we can accept for signing
        self.msg_paths = pop_list(j, 'msg_paths', cleanup_deriv_path)

        # free text shown at top
        self.notes = j.pop('notes', None)

        # time period, in minutes
        self.period = pop_int(j, 'period', 1, 3*24*60)

        # how many times they may view the long-secret
        self.allow_sl = pop_int(j, 'allow_sl', 1, 10)

        self.set_sl = pop_string(j, 'set_sl', 16, AE_LONG_SECRET_LEN-2)
        if self.set_sl:
            assert self.allow_sl, 'need allow_sl>=1'        # because pointless otherwise

        # complex txn approval rules
        lst = pop_list(j, 'rules') or []
        self.rules = [ApprovalRule(i, idx) for idx, i in enumerate(lst)]

        if not self.period and any(i.has_velocity for i in self.rules):
            raise ValueError("Needs period to be specified")

        # error checking, must be last!
        assert_empty_dict(j)

        # statistics / state
        self.refusals = 0
        self.approvals = 0
        self.sl_reads = 0
        self.pending_auth = {}
        self.need_pin = None

        # velocity limits
        self.current_period = utime.time() # starts now
        self.period_spent = 21E6

    def period_reset_time(self):
        # time from now, in seconds, until the period resets and the velocity
        # total is reset
        if not self.period: return 0
        end = self.current_period + (self.period*60)
        return utime.time() - end
        
    def save(self):
        # create JSON document for next time.
        simple = ['must_log', 'msg_paths', 'notes', 'period', 'allow_sl', 'warnings_ok']
        rv = dict()
        for fn in simple:
            rv[fn] = getattr(self, fn, None)

        rv['rules'] = [i.to_json() for i in self.rules]

        # never write this secret into JSON
        assert 'set_sl' not in rv

        return rv

    def log_refuse(self, msg):
        # when things fail
        self.log("REFUSED: " + msg)
        self.refusals += 1
        self.last_refusal = msg

    def log_approved(self, msg):
        # when things fail
        self.log("APPROVED: " + msg)
        self.approvals += 1
        self.last_refusal = None

    def log(self, msg):
        # try to write to SD card.
        print("HSM LOG: " + msg)
        pass

    def explain(self, fd):

        if self.notes:
            fd.write('=-=\n%s\n=-=\n' % self.notes)

        fd.write('\nTransactions:\n')
        if not self.rules:
            fd.write("- No transaction will be signed.\n")
        else:
            for r in self.rules:
                fd.write('- Rule #%d: %s\n' % (r.index+1, r.to_text()))

        if self.period:
            fd.write('\nVelocity Period:\n %d minutes' % self.period)
            if self.period >= 60:
                fd.write('\n = %.3g hrs' % (self.period / 60))
            fd.write('\n')

        fd.write('\nMessage signing:\n')
        if self.msg_paths:
            fd.write("- Allowed if path is: %s\n" % ' OR '.join(self.msg_paths))
        else:
            fd.write("- Not allowed.\n")

        fd.write('\nOther policy:\n')
        fd.write('- MicroSD card %s receive log entries.\n' % ('MUST' if self.must_log else 'will'))
        if self.set_sl:
            fd.write('- Storage Locker will be updated (once).\n')
        if self.allow_sl:
            fd.write('- Storage Locker can be read only %s.\n' 
                        % ('once' if self.allow_sl == 1 else ('%d times'%self.allow_sl)))
        if self.warnings_ok:
            fd.write('- PSBT warnings will be ignored.\n')

        self.summary = fd.getvalue()

    def status_report(self, rv):
        # Add some values we will share over USB during HSM operation
        for fn in ['summary', 'last_refusal', 'approvals', 'refusals', 'sl_reads', 'period']:
            rv[fn] = getattr(self, fn, None)

        if self.need_pin:
            rv['need_pin'] = self.need_pin

        # UX on web browser will need to know the local PIN code might be needed
        rv['uses_local_conf'] = any(r.local_conf for r in self.rules)

        # sensitive values, summarize only!
        rv['pending_auth'] = len(self.pending_auth)

    def activate(self):
        # user approved activation, so apply it.
        import main
        assert not main.hsm_active
        main.hsm_active = self

        # save the "long secret" ... probably only happens first time HSM policy
        # is activated, because we don't store that original value except here 
        # and in SE.
        if self.set_sl:
            from main import pa

            # add length half-word to start, and pad to max size
            tmp = bytearray(AE_LONG_SECRET_LEN)
            val = self.set_sl.encode('utf8')
            ustruct.pack_into('H', tmp, 0, len(val))
            tmp[2:2+len(self.set_sl)] = val

            # write it
            pa.ls_change(tmp)

            # memory cleanup
            blank_object(tmp)
            blank_object(val)
            blank_object(self.set_sl)
            self.set_sl = None

    def fetch_storage_locker(self):
        # USB request to read the storage locker (aka. long secret from 608a)
        # - limited by counter, because typically only needed at startup
        # - please keep in mind the desktop needs this secret, and probably blabs it
        # - our memory also is contaiminated with this secret, and no easy way to clean
        assert self.allow_sl, 'not allowed'
        assert self.sl_reads < self.allow_sl, 'consumed'
        self.sl_reads += 1

        from main import pa
        raw = pa.ls_fetch()
        ll, = ustruct.unpack_from('H', raw)
        assert 0 <= ll <= AE_LONG_SECRET_LEN-2

        return raw[2:2+ll]

    def usb_auth_user(self, username, token, totp_time):
        # User via USB has proposed a totp/user/password for auth purposes
        # - but just capture data at this point, we can't use until PSBT arrives
        # - reject bogus users at this point?
        # - to avoid timing attacks, keep this linear
        assert 1 < len(username) <= MAX_USERNAME_LEN, 'badlen'
        assert len(self.pending_auth)+1 <= MAX_NUMBER_USERS, 'toomany'

        self.pending_auth[username] = (token, totp_time)

    async def approve_msg_sign(self, msg_text, address, subpath):
        # Maybe approve indicated message to be signed.
        # return 'y' or 'x'
        self.log('Message signing requested: %d bytes to be signed by %s = %s' 
                            % (len(msg_text), subpath, address))
        if not self.msg_paths: 
            self.log_refuse("Message signing not permitted")
            return 'x'

        if subpath not in self.msg_paths:
            self.log_refuse('Message signing not enabled for that path')
            return 'x'

        self.log_approved('Message signing')
        return 'y'

    async def approve_transaction(self, psbt, psbt_sha, story):
        # Approve or don't a transaction. Catch assertions and other
        # reasons for failing/rejecting into the log.
        # - return 'y' or 'x'
        chain = chains.current_chain()

        self.log('Transaction signing requested\n-vvv-\n%s\n-^^^-' % story)

        # reset pending auth list and "consume" it now
        auth = self.pending_auth
        self.pending_auth = {}

        from hsm_ux import hsm_ux_obj
        auth['_local'] = (hsm_ux_obj.pop_digits(), 0)

        try:
            assert psbt_sha and len(psbt_sha) == 32

            if not self.rules:
                raise ValueError("no txn signing allowed")

            # reject anything with warning, probably
            if psbt.warnings:
                if self.warnings_ok:
                    self.log("Txn has warnings, but policy is to accept anyway.")
                else:
                    raise ValueError("has %d warning(s)" % len(psbt.warnings))

            # See who has entered creditials already (may not be valid, but enuf
            # for rule matching at this point).
            users = list(auth.keys())

            # Where is it going?
            total_out = 0
            dests = []
            for idx, tx_out in psbt.output_iter():
                if not psbt.outputs[idx].is_change:
                    total_out += tx_out.nValue
                    dests.append(chain.render_address(tx_out.scriptPubKey))

            # Pick a rule to apply to this specific txn
            reasons = []
            for rule in self.rules:
                try:
                    if rule.matches_transaction(psbt, users, total_out, dests):
                        break
                except BaseException as exc:
                    # let's not share these details, except for debug; since
                    # they are not errors, just picking best rule in priority order
                    r = "rule #%d: %s: %s" % (rule.index+1, problem_file_line(exc), str(exc))
                    reasons.append(r)
                    print(r)
            else:
                err = "HSM rejected: " + ', '.join(reasons)
                self.log_refuse(err)
                return 'x'

            # check those users gave good passwords

            # looks good, do it
            self.log_approved("Acceptable by rule #%d" % (rule.index+1))

            return 'y'
        except BaseException as exc:
            sys.print_exception(exc)
            err = "HSM rejected: %s: %s" % (problem_file_line(exc), str(exc))
            self.log_refuse(err)

            return 'x'
            
def hsm_status_report():
    # Return a JSON-able object. Documented and external programs
    # rely on this output... and yet, don't overshare either.
    from auth import UserAuthorizedAction
    from main import hsm_active
    from hsm_ux import ApproveHSMPolicy

    rv = dict()
    rv['active'] = bool(hsm_active)

    if not hsm_active:
        rv['policy_available'] = hsm_policy_available()

        ar = UserAuthorizedAction.active_request
        if ar and isinstance(ar, ApproveHSMPolicy):
            # we are waiting for local user to approve entry into HSM mode
            rv['approval_wait'] = True

        # provide some keys they will need when making their policy file!
        rv['wallets'] = [ms.name for ms in MultisigWallet.get_all()]
        rv['users'] = Users.list()

    if hsm_active:
        hsm_active.status_report(rv)

    return rv
        

# EOF
