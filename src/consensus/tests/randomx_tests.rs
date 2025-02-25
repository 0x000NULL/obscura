use crate::consensus::randomx::{RandomXContext, RandomXError, verify_difficulty};
use crate::consensus::randomx::randomx_vm::{RandomXVM, Instruction};
use std::collections::HashSet;

#[test]
fn test_randomx_context_creation() {
    let context = RandomXContext::new(b"test_key");
    assert!(context.is_valid());
}

#[test]
fn test_hash_computation() {
    let context = RandomXContext::new(b"test_key");
    let input = b"test block header";
    let mut output = [0u8; 32];
    
    assert!(context.calculate_hash(input, &mut output).is_ok());
    assert_ne!(output, [0u8; 32]);
}

#[test]
fn test_mining_simulation() {
    let context = RandomXContext::new(b"test_key");
    let mut hash = [0u8; 32];
    
    // Try multiple times to get a hash that meets the target
    // This is a realistic mining simulation
    let target = 0x207fffff;
    let mut input = b"test block header".to_vec();
    let mut nonce = 0u32;
    
    while nonce < 1000 {  // Limit attempts to avoid infinite loop in test
        input.extend_from_slice(&nonce.to_le_bytes());
        assert!(context.calculate_hash(&input, &mut hash).is_ok());
        
        if verify_difficulty(&hash, target) {
            // Found a valid hash
            assert!(verify_difficulty(&hash, target));
            return;
        }
        
        nonce += 1;
        input.truncate(input.len() - 4);  // Remove previous nonce
    }
    
    // If we reach here, we couldn't find a valid hash
    // This is unlikely but possible - you might want to adjust the target
    // or increase the number of attempts for more reliable tests
    panic!("Could not find valid hash within {} attempts", nonce);
}

#[test]
fn test_vm_instruction_set() {
    let mut vm = RandomXVM::new_with_mode(true);
    
    // Test arithmetic operations
    let program = vec![
        Instruction::Add(0, 1, 2),
        Instruction::Sub(3, 0, 1),
        Instruction::Mul(4, 2, 3),
        Instruction::Div(5, 4, 1),
    ];
    
    vm.registers[1] = 100;
    vm.registers[2] = 50;
    
    vm.load_program(program);
    assert!(vm.execute().is_ok());
    
    assert_eq!(vm.registers[0], 150);  // 100 + 50
    assert_eq!(vm.registers[3], 50);   // 150 - 100
    assert_eq!(vm.registers[4], 2500); // 50 * 50
    assert_eq!(vm.registers[5], 25);   // 2500 / 100
}

#[test]
fn test_memory_operations() {
    let mut vm = RandomXVM::new_with_mode(true);
    
    // Test memory read/write operations
    let program = vec![
        Instruction::Store(0x1000, 1),           // Store r1 to memory
        Instruction::Load(2, 0x1000),            // Load from memory to r2
        Instruction::ScratchpadWrite(0x100, 3),  // Write r3 to scratchpad
        Instruction::ScratchpadRead(4, 0x100),   // Read from scratchpad to r4
    ];
    
    vm.registers[1] = 0xDEADBEEF;
    vm.registers[3] = 0xCAFEBABE;
    
    vm.load_program(program);
    assert!(vm.execute().is_ok());
    
    assert_eq!(vm.registers[2], 0xDEADBEEF); // Value loaded from memory
    assert_eq!(vm.registers[4], 0xCAFEBABE); // Value loaded from scratchpad
}

#[test]
fn test_memory_hard_function_properties() {
    let mut vm = RandomXVM::new_with_mode(true);
    
    // Set initial state
    vm.registers[0] = 12345;
    
    // First memory mixing
    let initial_scratchpad = vm.scratchpad.clone();
    vm.mix_memory();
    let first_mix = vm.scratchpad.clone();
    
    // Verify memory-hard properties:
    // 1. Memory has been modified from initial state
    assert!(initial_scratchpad.iter().zip(first_mix.iter()).any(|(a, b)| a != b),
           "Memory mixing should modify the scratchpad");
    
    // 2. Different initial states produce different results
    vm.registers[0] = 54321;
    vm.mix_memory();
    let different_input_mix = vm.scratchpad.clone();
    assert!(first_mix.iter().zip(different_input_mix.iter()).any(|(a, b)| a != b),
           "Different inputs should produce different scratchpad states");
    
    // 3. Verify memory access patterns
    let zero_blocks = vm.scratchpad.chunks(64)
        .filter(|block| block.iter().all(|&x| x == 0))
        .count();
    assert!(zero_blocks < vm.scratchpad.len() / 64,
           "Memory should not contain too many zero blocks");
    
    // 4. Verify mixing entropy
    let unique_bytes: HashSet<_> = vm.scratchpad.iter().copied().collect();
    assert!(unique_bytes.len() > 100,
           "Memory mixing should produce diverse byte values");
}

#[test]
fn test_hash_generation() {
    let context = RandomXContext::new(b"test_key");
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];
    
    // Test 1: Same input produces same hash
    assert!(context.calculate_hash(b"test_input", &mut output1).is_ok());
    assert!(context.calculate_hash(b"test_input", &mut output2).is_ok());
    assert_eq!(output1, output2);
    
    // Test 2: Different inputs produce different hashes
    assert!(context.calculate_hash(b"different_input", &mut output2).is_ok());
    assert_ne!(output1, output2);
    
    // Test 3: Hash output properties
    assert!(output1.iter().any(|&x| x != 0)); // Not all zeros
    assert!(output2.iter().any(|&x| x != 0)); // Not all zeros
}

#[test]
fn test_program_generation() {
    let context = RandomXContext::new(b"test_key");
    
    // Test 1: Program generation from input
    let program = context.generate_program(b"test_input");
    assert!(!program.is_empty());
    
    // Test 2: Same input produces same program
    let program2 = context.generate_program(b"test_input");
    assert_eq!(program, program2);
    
    // Test 3: Different inputs produce different programs
    let program3 = context.generate_program(b"different_input");
    assert_ne!(program, program3);
    
    // Test 4: Program contains variety of instructions
    let instruction_types: HashSet<_> = program.iter()
        .map(|inst| std::mem::discriminant(inst))
        .collect();
    assert!(instruction_types.len() > 1); // More than one type of instruction
}

#[test]
fn test_error_handling() {
    let mut vm = RandomXVM::new_with_mode(true);
    
    // Test 1: Empty program execution
    assert!(vm.execute().is_ok());
    
    // Test 2: Program counter bounds
    vm.pc = usize::MAX;
    assert!(vm.step().is_err());
    
    // Test 3: Invalid memory access
    let program = vec![
        Instruction::ScratchpadRead(0, u32::MAX), // Should wrap around due to modulo
    ];
    vm.load_program(program);
    assert!(vm.execute().is_ok()); // Should not panic
}

#[test]
fn test_context_lifecycle() {
    // Test 1: Context creation and destruction
    let context = RandomXContext::new(b"test_key");
    assert!(context.is_valid());
    
    // Test 2: Multiple contexts
    let context2 = RandomXContext::new(b"different_key");
    assert!(context2.is_valid());
    
    // Test 3: Context independence
    let mut output1 = [0u8; 32];
    let mut output2 = [0u8; 32];
    
    let context1 = RandomXContext::new(b"key1");
    let context2 = RandomXContext::new(b"key2");
    
    assert!(context1.calculate_hash(b"input", &mut output1).is_ok());
    assert!(context2.calculate_hash(b"input", &mut output2).is_ok());
    
    assert_ne!(output1, output2); // Different keys should produce different hashes
} 