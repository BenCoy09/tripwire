// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Reference security token with configurable transfer restrictions.
/// One codebase, two builds: the flags below reproduce the "as deployed"
/// (defective) token and the "patched" token that Tripwire attacks.
///
/// Planted defects in the deployed build:
///   1. Parameter drift:   lock-up is 180 days, the terms promise 360.
///   2. Bypass path:       transferFrom() skips the accredited-investor check.
///   3. Missing check:     the holder cap is enforced at issuance only.
contract RestrictedToken {
    string public name;
    string public symbol;
    uint8 public constant decimals = 0;
    uint256 public totalSupply;
    uint256 public holders;

    address public immutable admin;
    uint256 public immutable lockup;                 // seconds
    uint256 public immutable holderCap;              // 0 = unlimited
    bool public immutable accreditedOnTransferFrom;  // defect 2 when false
    bool public immutable capOnTransfer;             // defect 3 when false

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public accredited;
    mapping(address => bytes2) public countryOf;     // ISO 3166 alpha-2 as bytes2
    mapping(address => uint256) public lockStart;    // first receipt of tokens
    mapping(bytes2 => bool) public blocked;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    modifier onlyAdmin() {
        require(msg.sender == admin, "NotAdmin");
        _;
    }

    constructor(
        string memory n,
        string memory s,
        uint256 lockupDays,
        uint256 cap,
        bool accFrom,
        bool capOnTx,
        bytes2[] memory blockedList
    ) {
        name = n;
        symbol = s;
        admin = msg.sender;
        lockup = lockupDays * 1 days;
        holderCap = cap;
        accreditedOnTransferFrom = accFrom;
        capOnTransfer = capOnTx;
        for (uint256 i = 0; i < blockedList.length; i++) blocked[blockedList[i]] = true;
    }

    function register(address who, bool acc, bytes2 cc) external onlyAdmin {
        accredited[who] = acc;
        countryOf[who] = cc;
    }

    function issue(address to, uint256 amount) external onlyAdmin {
        require(accredited[to], "NotAccredited");
        require(!blocked[countryOf[to]], "BlockedJurisdiction");
        if (balanceOf[to] == 0 && holderCap != 0) require(holders < holderCap, "HolderCapReached");
        _credit(to, amount);
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount, false);
        return true;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        require(a >= amount, "NoAllowance");
        if (a != type(uint256).max) allowance[from][msg.sender] = a - amount;
        _move(from, to, amount, true);
        return true;
    }

    function _move(address from, address to, uint256 amount, bool viaSpender) internal {
        require(balanceOf[from] >= amount, "Balance");
        require(block.timestamp >= lockStart[from] + lockup, "LockupActive");
        if (!viaSpender || accreditedOnTransferFrom) require(accredited[to], "NotAccredited");
        require(!blocked[countryOf[to]], "BlockedJurisdiction");
        if (capOnTransfer && holderCap != 0 && balanceOf[to] == 0) {
            require(holders < holderCap, "HolderCapReached");
        }
        balanceOf[from] -= amount;
        if (balanceOf[from] == 0) holders--;
        _credit(to, amount);
        emit Transfer(from, to, amount);
    }

    function _credit(address to, uint256 amount) internal {
        if (balanceOf[to] == 0) {
            holders++;
            if (lockStart[to] == 0) lockStart[to] = block.timestamp;
        }
        balanceOf[to] += amount;
    }
}
