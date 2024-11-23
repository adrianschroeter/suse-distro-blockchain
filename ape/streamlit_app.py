import streamlit as st
from web3_script import *

st.title('Web3 Contract Interaction')

st.header('Function: add_product')
name = st.text_input('Enter name', key='add_product_name')
git_ref = st.text_input('Enter git_ref', key='add_product_git_ref')
if st.button('Execute add_product', key='add_product_button'):
    result = add_product(name, git_ref)
    st.write(f'Result: {result}')

st.header('Function: add_product_build')
git_ref = st.text_input('Enter git_ref', key='add_product_build_git_ref')
kind = st.number_input('Enter kind', step=1, key='add_product_build_kind')
verification = st.text_input('Enter verification', key='add_product_build_verification')
if st.button('Execute add_product_build', key='add_product_build_button'):
    result = add_product_build(git_ref, kind, verification)
    st.write(f'Result: {result}')

st.header('Function: get_product')
product_id = st.number_input('Enter product_id', step=1, key='get_product_product_id')
if st.button('Execute get_product', key='get_product_button'):
    result = get_product(product_id)
    st.write(f'Result: {result}')

st.header('Function: get_product_build')
verification = st.text_input('Enter verification', key='get_product_build_verification')
if st.button('Execute get_product_build', key='get_product_build_button'):
    result = get_product_build(verification)
    st.write(f'Result: {result}')

st.header('Function: current_product_build')
name = st.text_input('Enter name', key='current_product_build_name')
kind = st.number_input('Enter kind', step=1, key='current_product_build_kind')
if st.button('Execute current_product_build', key='current_product_build_button'):
    result = current_product_build(name, kind)
    st.write(f'Result: {result}')

st.header('Function: get_product_counter')
if st.button('Execute get_product_counter', key='get_product_counter_button'):
    result = get_product_counter()
    st.write(f'Result: {result}')

st.header('Function: set_critical')
product_id = st.number_input('Enter product_id', step=1, key='set_critical_product_id')
critical = st.text_input('Enter critical', key='set_critical_critical')
if st.button('Execute set_critical', key='set_critical_button'):
    result = set_critical(product_id, critical)
    st.write(f'Result: {result}')

st.header('Function: add_attestation')
verification = st.text_input('Enter verification', key='add_attestation_verification')
if st.button('Execute add_attestation', key='add_attestation_button'):
    result = add_attestation(verification)
    st.write(f'Result: {result}')

st.header('Function: foundation_owner')
if st.button('Execute foundation_owner', key='foundation_owner_button'):
    result = foundation_owner()
    st.write(f'Result: {result}')

st.header('Function: product_creator')
if st.button('Execute product_creator', key='product_creator_button'):
    result = product_creator()
    st.write(f'Result: {result}')

st.header('Function: official_validator')
if st.button('Execute official_validator', key='official_validator_button'):
    result = official_validator()
    st.write(f'Result: {result}')

st.header('Function: security_team')
if st.button('Execute security_team', key='security_team_button'):
    result = security_team()
    st.write(f'Result: {result}')

st.header('Function: next_product')
if st.button('Execute next_product', key='next_product_button'):
    result = next_product()
    st.write(f'Result: {result}')

