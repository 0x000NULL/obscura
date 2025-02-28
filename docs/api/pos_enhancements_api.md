# Proof of Stake Enhancements API Documentation

## DelegationMarketplace

### Constructor
```rust
pub fn new() -> Self
```
Creates a new instance of the DelegationMarketplace.

### Methods

#### create_listing
```rust
pub fn create_listing(&mut self, listing: MarketplaceListing) -> Result<(), String>
```
Creates a new delegation listing in the marketplace.
- **Parameters:**
  - `listing`: The listing to create
- **Returns:** Result indicating success or error message
- **Errors:** If listing ID already exists

#### get_listing
```rust
pub fn get_listing(&self, id: &str) -> Option<&MarketplaceListing>
```
Retrieves a listing by its ID.
- **Parameters:**
  - `id`: The listing ID to retrieve
- **Returns:** Optional reference to the listing

#### create_offer
```rust
pub fn create_offer(&mut self, offer: MarketplaceOffer) -> Result<(), String>
```
Creates a new offer for a listing.
- **Parameters:**
  - `offer`: The offer to create
- **Returns:** Result indicating success or error message
- **Errors:** If referenced listing doesn't exist

#### complete_transaction
```rust
pub fn complete_transaction(&mut self, transaction: MarketplaceTransaction) -> Result<(), String>
```
Completes a delegation transaction.
- **Parameters:**
  - `transaction`: The transaction to complete
- **Returns:** Result indicating success or error message
- **Errors:** If referenced offer doesn't exist

## ValidatorReputationManager

### Constructor
```rust
pub fn new() -> Self
```
Creates a new instance of the ValidatorReputationManager.

### Methods

#### update_reputation
```rust
pub fn update_reputation(&mut self, validator_id: String, assessment: ReputationAssessment)
```
Updates a validator's reputation score.
- **Parameters:**
  - `validator_id`: The validator's ID
  - `assessment`: New reputation assessment
- **Effects:** Updates reputation scores and maintains bounded history

#### get_reputation
```rust
pub fn get_reputation(&self, validator_id: &str) -> Option<&ReputationScore>
```
Retrieves a validator's reputation score.
- **Parameters:**
  - `validator_id`: The validator's ID
- **Returns:** Optional reference to reputation score

#### add_oracle
```rust
pub fn add_oracle(&mut self, oracle: ReputationOracle)
```
Adds a new reputation oracle.
- **Parameters:**
  - `oracle`: The oracle to add

## StakeCompoundingManager

### Constructor
```rust
pub fn new() -> Self
```
Creates a new instance of the StakeCompoundingManager.

### Methods

#### set_config
```rust
pub fn set_config(&mut self, validator_id: String, config: CompoundingConfig)
```
Sets compounding configuration for a validator.
- **Parameters:**
  - `validator_id`: The validator's ID
  - `config`: Compounding configuration

#### start_operation
```rust
pub fn start_operation(&mut self, operation: CompoundingOperation) -> Result<(), String>
```
Starts a new compounding operation.
- **Parameters:**
  - `operation`: The operation to start
- **Returns:** Result indicating success or error message
- **Errors:** If operation ID already exists

#### update_status
```rust
pub fn update_status(&mut self, operation_id: &str, status: CompoundingStatus) -> Result<(), String>
```
Updates the status of a compounding operation.
- **Parameters:**
  - `operation_id`: The operation's ID
  - `status`: New status
- **Returns:** Result indicating success or error message
- **Errors:** If operation not found

## ValidatorDiversityManager

### Constructor
```rust
pub fn new() -> Self
```
Creates a new instance of the ValidatorDiversityManager.

### Methods

#### update_metrics
```rust
pub fn update_metrics(&mut self, metrics: DiversityMetrics)
```
Updates diversity metrics.
- **Parameters:**
  - `metrics`: New diversity metrics

#### add_validator_geo
```rust
pub fn add_validator_geo(&mut self, validator_id: String, geo_info: ValidatorGeoInfo)
```
Adds geographic information for a validator.
- **Parameters:**
  - `validator_id`: The validator's ID
  - `geo_info`: Geographic information

#### update_entity_info
```rust
pub fn update_entity_info(&mut self, entity_id: String, info: EntityInfo)
```
Updates entity information.
- **Parameters:**
  - `entity_id`: The entity's ID
  - `info`: Entity information

#### get_distribution_report
```rust
pub fn get_distribution_report(&self) -> GeoDistributionReport
```
Generates a geographic distribution report.
- **Returns:** Current distribution report

#### get_validator_geo
```rust
pub fn get_validator_geo(&self, validator_id: &str) -> Option<&ValidatorGeoInfo>
```
Retrieves geographic information for a validator.
- **Parameters:**
  - `validator_id`: The validator's ID
- **Returns:** Optional reference to geographic information

## HardwareSecurityManager

### Constructor
```rust
pub fn new(required_level: u32) -> Self
```
Creates a new instance of the HardwareSecurityManager.
- **Parameters:**
  - `required_level`: Minimum required security level

### Methods

#### add_security_info
```rust
pub fn add_security_info(&mut self, validator_id: String, info: HardwareSecurityInfo) -> Result<(), String>
```
Adds security information for a validator.
- **Parameters:**
  - `validator_id`: The validator's ID
  - `info`: Security information
- **Returns:** Result indicating success or error message
- **Errors:** If security level is insufficient

#### add_attestation
```rust
pub fn add_attestation(&mut self, attestation: SecurityAttestation)
```
Adds a security attestation.
- **Parameters:**
  - `attestation`: The attestation to add

#### verify_security_level
```rust
pub fn verify_security_level(&self, validator_id: &str) -> bool
```
Verifies if a validator meets security requirements.
- **Parameters:**
  - `validator_id`: The validator's ID
- **Returns:** Whether security level is sufficient

#### get_security_info
```rust
pub fn get_security_info(&self, validator_id: &str) -> Option<&HardwareSecurityInfo>
```
Retrieves security information for a validator.
- **Parameters:**
  - `validator_id`: The validator's ID
- **Returns:** Optional reference to security information

## ContractVerificationManager

### Constructor
```rust
pub fn new() -> Self
```
Creates a new instance of the ContractVerificationManager.

### Methods

#### add_verified_contract
```rust
pub fn add_verified_contract(&mut self, contract: VerifiedContract)
```
Adds a verified contract.
- **Parameters:**
  - `contract`: The verified contract to add

#### update_verification_status
```rust
pub fn update_verification_status(&mut self, status: VerificationStatus)
```
Updates verification status.
- **Parameters:**
  - `status`: New verification status

#### is_contract_verified
```rust
pub fn is_contract_verified(&self, contract_id: &str) -> bool
```
Checks if a contract is verified.
- **Parameters:**
  - `contract_id`: The contract's ID
- **Returns:** Whether contract is verified

## ProofOfStake Integration

### Constructor
```rust
pub fn new() -> Self
```
Creates a new instance of the ProofOfStake system with all enhancements.

### Methods

#### update_enhancements
```rust
pub fn update_enhancements(&mut self, current_time: u64) -> Result<(), String>
```
Updates all enhancement components.
- **Parameters:**
  - `current_time`: Current timestamp
- **Returns:** Result indicating success or error message

#### validate_new_validator
```rust
pub fn validate_new_validator(&self, validator_id: &[u8]) -> Result<(), String>
```
Validates a new validator against all enhancement requirements.
- **Parameters:**
  - `validator_id`: The validator's ID
- **Returns:** Result indicating success or error message
- **Errors:**
  - If reputation score is too low
  - If security level is insufficient
  - If geographic distribution requirements not met
  - If no security attestation found 