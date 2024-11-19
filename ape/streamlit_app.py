import streamlit as st
from web3_script import *

st.title('Web3 Contract Interaction')

st.header('Function: adduser')
_user = st.text_input('Enter _user', key='adduser__user')
if st.button('Execute adduser', key='adduser_button'):
    result = adduser(_user)
    st.write(f'Result: {result}')

st.header('Function: getuser')
_user = st.text_input('Enter _user', key='getuser__user')
if st.button('Execute getuser', key='getuser_button'):
    result = getuser(_user)
    st.write(f'Result: {result}')

st.header('Function: set_balance')
_user = st.text_input('Enter _user', key='set_balance__user')
_amount = st.number_input('Enter _amount', step=1, key='set_balance__amount')
if st.button('Execute set_balance', key='set_balance_button'):
    result = set_balance(_user, _amount)
    st.write(f'Result: {result}')

st.header('Function: balances')
arg0 = st.text_input('Enter arg0', key='balances_arg0')
if st.button('Execute balances', key='balances_button'):
    result = balances(arg0)
    st.write(f'Result: {result}')

