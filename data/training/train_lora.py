#!/usr/bin/env python3
"""AUTARCH LoRA Training Script (Transformers + PEFT)"""
import json
import torch
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM, AutoTokenizer, TrainingArguments,
    BitsAndBytesConfig,
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

# Quantization config
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.float16,
    bnb_4bit_use_double_quant=True,
) if True else None

print("Loading base model: models/Hal_v2.gguf")
model = AutoModelForCausalLM.from_pretrained(
    "models/Hal_v2.gguf",
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=False,
)
tokenizer = AutoTokenizer.from_pretrained("models/Hal_v2.gguf", trust_remote_code=False)
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

if True:
    model = prepare_model_for_kbit_training(model)

# LoRA config
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    lora_dropout=0.05,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                     "gate_proj", "up_proj", "down_proj"],
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# Load dataset
samples = []
with open("C:\she\autarch\data\training\autarch_dataset_20260302_202634.jsonl", "r") as f:
    for line in f:
        samples.append(json.loads(line))

def format_sample(sample):
    if "conversations" in sample:
        msgs = sample["conversations"]
        text = ""
        for msg in msgs:
            role = "user" if msg["from"] == "human" else "assistant"
            text += f"<|im_start|>{role}\n{msg['value']}<|im_end|>\n"
        return {"text": text}
    else:
        return {"text": f"<|im_start|>user\n{sample['instruction']}\n{sample.get('input','')}<|im_end|>\n<|im_start|>assistant\n{sample['output']}<|im_end|>\n"}

dataset = Dataset.from_list([format_sample(s) for s in samples])
print(f"Dataset: {len(dataset)} samples")

# Train
trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=2048,
    args=TrainingArguments(
        output_dir="C:\she\autarch\data\training\output",
        num_train_epochs=3,
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        learning_rate=0.0002,
        warmup_ratio=0.03,
        save_steps=50,
        logging_steps=10,
        fp16=True,
        optim="adamw_8bit",
        report_to="none",
    ),
)

print("Starting training...")
trainer.train()
print("Training complete!")

# Save
model.save_pretrained("C:\she\autarch\data\training\output/lora_adapter")
tokenizer.save_pretrained("C:\she\autarch\data\training\output/lora_adapter")
print(f"LoRA adapter saved to C:\she\autarch\data\training\output/lora_adapter")
