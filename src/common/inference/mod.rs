#![allow(dead_code)]

pub mod api_keys;
mod batch_processing;
mod batch_processing_grpc;
pub mod bm25;
pub(crate) mod config;
mod infer_processing;
pub mod inference_input;
mod local_model;
pub mod params;
pub mod query_requests_grpc;
pub mod query_requests_rest;
pub mod service;
pub mod update_requests;

pub(crate) use batch_processing::{
    reject_group_inference_inputs_for_encrypted_vectors,
    reject_inference_inputs_for_encrypted_vectors,
};
