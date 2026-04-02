// SPDX-License-Identifier: MIT
// Agentic Commerce with hook extension — optional hook contract per job for extensibility
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./IACPHook.sol";

/**
 * @title AgenticCommerceHooked
 * @dev Agentic Commerce with optional hook support.
 *      Same lifecycle as AgenticCommerce (Open -> Funded -> Submitted -> Completed | Rejected | Expired)
 *      but adds: hook address per job, optParams on hookable functions, beforeAction/afterAction callbacks.
 *      claimRefund is deliberately NOT hookable — safety mechanism so refunds cannot be blocked.
 */
contract AgenticCommerceHooked is AccessControl, ReentrancyGuard {
    using SafeERC20 for IERC20;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    uint256 public constant HOOK_GAS_LIMIT = 500_000;

    enum JobStatus {
        Open,
        Funded,
        Submitted,
        Completed,
        Rejected,
        Expired
    }

    struct Job {
        uint256 id;
        address client;
        address provider;
        address evaluator;
        address hook; // optional hook contract (address(0) = no hook)
        string description;
        uint256 budget;
        uint256 expiredAt;
        JobStatus status;
    }

    IERC20 public paymentToken;
    uint256 public platformFeeBP; // 10000 = 100%
    address public platformTreasury;

    mapping(uint256 => Job) public jobs;
    uint256 public jobCounter;

    event JobCreated(
        uint256 indexed jobId,
        address indexed client,
        address indexed provider,
        address evaluator,
        uint256 expiredAt,
        address hook
    );
    event ProviderSet(uint256 indexed jobId, address indexed provider);
    event BudgetSet(uint256 indexed jobId, uint256 amount);
    event JobFunded(uint256 indexed jobId, address indexed client, uint256 amount);
    event JobSubmitted(uint256 indexed jobId, address indexed provider, bytes32 deliverable);
    event JobCompleted(uint256 indexed jobId, address indexed evaluator, bytes32 reason);
    event JobRejected(uint256 indexed jobId, address indexed rejector, bytes32 reason);
    event JobExpired(uint256 indexed jobId);
    event PaymentReleased(uint256 indexed jobId, address indexed provider, uint256 amount);
    event Refunded(uint256 indexed jobId, address indexed client, uint256 amount);

    error InvalidJob();
    error WrongStatus();
    error Unauthorized();
    error ZeroAddress();
    error ExpiryTooShort();
    error ZeroBudget();
    error BudgetMismatch();
    error ProviderNotSet();

    constructor(address paymentToken_, address treasury_) {
        if (paymentToken_ == address(0) || treasury_ == address(0)) revert ZeroAddress();
        paymentToken = IERC20(paymentToken_);
        platformTreasury = treasury_;
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    function setPlatformFee(uint256 feeBP_, address treasury_) external onlyRole(ADMIN_ROLE) {
        if (treasury_ == address(0)) revert ZeroAddress();
        if (feeBP_ > 10000) revert InvalidJob();
        platformFeeBP = feeBP_;
        platformTreasury = treasury_;
    }

    // --- Hook helpers --------------------------------------------------------

    function _beforeHook(address hook, uint256 jobId, bytes4 selector, bytes memory data) internal {
        if (hook != address(0)) {
            IACPHook(hook).beforeAction{gas: HOOK_GAS_LIMIT}(jobId, selector, data);
        }
    }

    function _afterHook(address hook, uint256 jobId, bytes4 selector, bytes memory data) internal {
        if (hook != address(0)) {
            IACPHook(hook).afterAction{gas: HOOK_GAS_LIMIT}(jobId, selector, data);
        }
    }

    // --- Core functions ------------------------------------------------------

    function createJob(
        address provider,
        address evaluator,
        uint256 expiredAt,
        string calldata description,
        address hook
    ) external returns (uint256 jobId) {
        if (evaluator == address(0)) revert ZeroAddress();
        if (expiredAt <= block.timestamp + 5 minutes) revert ExpiryTooShort();
        jobId = ++jobCounter;
        jobs[jobId] = Job({
            id: jobId,
            client: msg.sender,
            provider: provider,
            evaluator: evaluator,
            hook: hook,
            description: description,
            budget: 0,
            expiredAt: expiredAt,
            status: JobStatus.Open
        });
        emit JobCreated(jobId, msg.sender, provider, evaluator, expiredAt, hook);
        return jobId;
    }

    /// @dev Client sets provider when job was created with provider == address(0).
    function setProvider(uint256 jobId, address provider_, bytes calldata optParams) external {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status != JobStatus.Open) revert WrongStatus();
        if (msg.sender != job.client) revert Unauthorized();
        if (job.provider != address(0)) revert WrongStatus(); // already set
        if (provider_ == address(0)) revert ZeroAddress();
        bytes memory data = abi.encode(msg.sender, provider_, optParams);
        _beforeHook(job.hook, jobId, msg.sig, data);
        job.provider = provider_;
        emit ProviderSet(jobId, provider_);
        _afterHook(job.hook, jobId, msg.sig, data);
    }

    function setBudget(uint256 jobId, uint256 amount, bytes calldata optParams) external {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status != JobStatus.Open) revert WrongStatus();
        if (msg.sender != job.client && msg.sender != job.provider) revert Unauthorized();
        bytes memory data = abi.encode(msg.sender, amount, optParams);
        _beforeHook(job.hook, jobId, msg.sig, data);
        job.budget = amount;
        emit BudgetSet(jobId, amount);
        _afterHook(job.hook, jobId, msg.sig, data);
    }

    function fund(uint256 jobId, uint256 expectedBudget, bytes calldata optParams) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status != JobStatus.Open) revert WrongStatus();
        if (msg.sender != job.client) revert Unauthorized();
        if (job.provider == address(0)) revert ProviderNotSet();
        if (job.budget == 0) revert ZeroBudget();
        if (job.budget != expectedBudget) revert BudgetMismatch();
        bytes memory fundData = abi.encode(msg.sender, optParams);
        _beforeHook(job.hook, jobId, msg.sig, fundData);
        job.status = JobStatus.Funded;
        paymentToken.safeTransferFrom(job.client, address(this), job.budget);
        emit JobFunded(jobId, job.client, job.budget);
        _afterHook(job.hook, jobId, msg.sig, fundData);
    }

    /// @dev Provider submits work, moving the job from Funded to Submitted.
    function submit(uint256 jobId, bytes32 deliverable, bytes calldata optParams) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status != JobStatus.Funded) revert WrongStatus();
        if (msg.sender != job.provider) revert Unauthorized();
        bytes memory data = abi.encode(msg.sender, deliverable, optParams);
        _beforeHook(job.hook, jobId, msg.sig, data);
        job.status = JobStatus.Submitted;
        emit JobSubmitted(jobId, msg.sender, deliverable);
        _afterHook(job.hook, jobId, msg.sig, data);
    }

    function complete(uint256 jobId, bytes32 reason, bytes calldata optParams) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status != JobStatus.Submitted) revert WrongStatus();
        if (msg.sender != job.evaluator) revert Unauthorized();
        bytes memory data = abi.encode(msg.sender, reason, optParams);
        _beforeHook(job.hook, jobId, msg.sig, data);
        job.status = JobStatus.Completed;
        uint256 amount = job.budget;
        uint256 fee = (amount * platformFeeBP) / 10000;
        uint256 net = amount - fee;
        if (fee > 0) {
            paymentToken.safeTransfer(platformTreasury, fee);
        }
        if (net > 0) {
            paymentToken.safeTransfer(job.provider, net);
        }
        emit JobCompleted(jobId, msg.sender, reason);
        emit PaymentReleased(jobId, job.provider, net);
        _afterHook(job.hook, jobId, msg.sig, data);
    }

    /// @dev Client may reject when Open; evaluator may reject when Funded or Submitted.
    function reject(uint256 jobId, bytes32 reason, bytes calldata optParams) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status == JobStatus.Open) {
            if (msg.sender != job.client) revert Unauthorized();
        } else if (job.status == JobStatus.Funded || job.status == JobStatus.Submitted) {
            if (msg.sender != job.evaluator) revert Unauthorized();
        } else {
            revert WrongStatus();
        }
        bytes memory data = abi.encode(msg.sender, reason, optParams);
        _beforeHook(job.hook, jobId, msg.sig, data);
        JobStatus prev = job.status;
        job.status = JobStatus.Rejected;
        if ((prev == JobStatus.Funded || prev == JobStatus.Submitted) && job.budget > 0) {
            paymentToken.safeTransfer(job.client, job.budget);
            emit Refunded(jobId, job.client, job.budget);
        }
        emit JobRejected(jobId, msg.sender, reason);
        _afterHook(job.hook, jobId, msg.sig, data);
    }

    /// @dev Deliberately NOT hookable — safety mechanism so refunds cannot be blocked.
    function claimRefund(uint256 jobId) external nonReentrant {
        Job storage job = jobs[jobId];
        if (job.id == 0) revert InvalidJob();
        if (job.status != JobStatus.Funded && job.status != JobStatus.Submitted) revert WrongStatus();
        if (block.timestamp < job.expiredAt) revert WrongStatus();
        job.status = JobStatus.Expired;
        if (job.budget > 0) {
            paymentToken.safeTransfer(job.client, job.budget);
            emit Refunded(jobId, job.client, job.budget);
        }
        emit JobExpired(jobId);
    }

    function getJob(uint256 jobId) external view returns (Job memory) {
        return jobs[jobId];
    }
}
