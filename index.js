const convert = require('xml-js');
const fetch = require('node-fetch');
const CryptoJS = require('./CryptoJS.js');
const R = require('ramda');




/*
function login(destnation, callback, redirectDes) {
	var name = $.trim($('#username').val());
	var psd = $('#password').val();
	var valid = validateInput(name, psd);
	if (!valid) {
		return;
	}
	refreshToken();
	if ($.isArray(g_requestVerificationToken)) {
		if (g_requestVerificationToken.length <= 0) {
			setTimeout(function () {
				if (g_requestVerificationToken.length > 0) {
					login(destnation, callback, redirectDes);
				}
			}, 50)
			return;
		}
	}
	var scram = CryptoJS.SCRAM();
	var firstNonce = scram.nonce().toString();
	var firstPostData = {
		username: name,
		firstnonce: firstNonce,
		mode: RSA_LOGIN_MODE
	};
	var firstXml = object2xml('request', firstPostData);
	saveAjaxData('api/user/challenge_login', firstXml, function ($xml) {
		var ret = xml2object($xml);
		if (ret.type == 'response') {
			var salt = CryptoJS.enc.Hex.parse(ret.response.salt);
			var iter = ret.response.iterations;
			var finalNonce = ret.response.servernonce;
			var authMsg = firstNonce + "," + finalNonce + "," + finalNonce;
			var saltPassword = scram.saltedPassword(psd, salt, iter).toString();
			var clientProof = scram.clientProof(psd, salt, iter, authMsg);
			var serverKey = scram.serverKey(CryptoJS.enc.Hex.parse(saltPassword)).toString();
			var finalPostData = {
				clientproof: clientProof,
				finalnonce: finalNonce
			};
			if (ret.response.newType && ret.response.newType == '1') {
				var newSalt = CryptoJS.enc.Hex.parse(ret.response.newSalt);
				var newIter = ret.response.newIterations;
				var newSaltPassword = scram.saltedPassword(psd, newSalt, newIter).toString();
				var newStoredKey = scram.storedKey(scram.clientKey(CryptoJS.enc.Hex.parse(newSaltPassword))).toString();
				var newServerKey = scram.serverKey(CryptoJS.enc.Hex.parse(newSaltPassword)).toString();
				var hashOldNewPwd = SHA256(newStoredKey + newServerKey + clientProof);
				finalPostData = {
					clientproof: clientProof,
					finalnonce: finalNonce,
					hashOldNewPwd: hashOldNewPwd,
					newStoredKey: newStoredKey,
					newServerKey: newServerKey
				}
			}
			var finalXml = object2xml('request', finalPostData);
			saveAjaxData('api/user/authentication_login', finalXml, function ($xml) {
				ret = xml2object($xml);
				if (ret.type == 'response') {
					var serverProof = scram.serverProof(psd, salt, iter, authMsg);
					if (ret.response.serversignature == serverProof) {
						var publicKeySignature = scram.signature(CryptoJS.enc.Hex.parse(ret.response.rsan), CryptoJS.enc.Hex.parse(serverKey)).toString();
						if (ret.response.rsapubkeysignature == publicKeySignature) {
							g_encPublickey.e = ret.response.rsae;
							g_encPublickey.n = ret.response.rsan;
							storagePubkey(g_encPublickey.n, g_encPublickey.e);
							getAjaxData('api/user/state-login', function ($xml) {
								var ret = xml2object($xml);
								if (ret.type == 'response') {
									g_default_password_status = parseInt(ret.response.firstlogin, 10);
									$('#username_span').text(name);
									$('#username_span').show();
									$('#logout_span').text(common_logout);
									var passwordStr = $('#password').val();
									clearDialog();
									g_main_displayingPromptStack.pop();
									startLogoutTimer(redirectDes);
									if (g_default_password_status == 0) {
										if (current_href == 'quicksetup') {
											window.location.reload();
										} else if (current_href != 'pincoderequired' && current_href != 'pukrequired' && current_href != 'simlockrequired' && current_href != 'nocard' && current_href != 'cradleDisconnected' && current_href != 'commend') {
											gotoPageWithoutHistory("modifypassword.html");
										}
									} else {
										if (checkPWRemind(passwordStr, null, null)) {
											checkDialogFlag = true;
											if (g_show_password_remind != 1) {
												showPWRemindDialog(destnation, callback);
											}
										} else {
											loginSwitchDoing(destnation, callback);
										}
									}
									if (typeof(ret.response.userlevel) != 'undefined' && ret.response.userlevel == '1') {
										$("#menu_sms").hide();
										$("#show_psk_password").hide();
										$("#show_wep_password").hide();
									} else {
										$("#menu_sms").show();
										$("#show_psk_password").show();
										$("#show_wep_password").show();
										if (g_restore_default_status == '1') {
											$("#menu_sms").hide();
										}
									}
								}
							});
						} else {
							showErrorUnderTextbox('username', IDS_login_fialed_prompt);
							$('#username').focus();
							$('#username').val('');
							$('#password').val('');
						}
					} else {
						showErrorUnderTextbox('username', IDS_login_fialed_prompt);
						$('#username').focus();
						$('#username').val('');
						$('#password').val('');
					}
				} else {
					if (ret.error.code == ERROR_LOGIN_USERNAME_PWD_ORERRUN) {
						showErrorUnderTextbox('forget_password_tab', IDS_login_username_password_input_overrun);
						$('#username').focus();
						$('#username').val('');
						$('#password').val('');
					} else if (ret.error.code == ERROR_LOGIN_USERNAME_PWD_WRONG) {
						showErrorUnderTextbox('forget_password_tab', IDS_login_username_password_wrong);
						$('#username').focus();
						$('#username').val('');
						$('#password').val('');
					}
				}
			});
		} else {
			if (ret.error.code == ERROR_LOGIN_USERNAME_PWD_ORERRUN) {
				showErrorUnderTextbox('forget_password_tab', IDS_login_username_password_input_overrun);
				$('#username').focus();
				$('#username').val('');
				$('#password').val('');
			} else if (ret.error.code == ERROR_LOGIN_USERNAME_PWD_WRONG) {
				showErrorUnderTextbox('forget_password_tab', IDS_login_username_password_wrong);
				$('#username').focus();
				$('#username').val('');
				$('#password').val('');
			} else if (ret.error.code == ERROR_LOGIN_ALREADY_LOGIN) {
				showErrorUnderTextbox('forget_password_tab', IDS_touch_user_login_repeat);
				$('#username').focus();
				$('#username').val('');
				$('#password').val('');
			} else if (ret.error.code == ERROR_LOGIN_FREQUENTLY_LOGIN) {
				showErrorUnderTextbox('forget_password_tab', IDS_login_frequently_warning);
				$('#username').focus();
				$('#username').val('');
				$('#password').val('');
			}
		}
	});
}
*/

//Huawei account data
const username = "admin";
const RSA_LOGIN_MODE = '1';
var password = "123456";
var mode=RSA_LOGIN_MODE

var SessionID=null;
var extractToken=R.path(['response','token','_text']);


fetch('http://192.168.8.1').then(res=>{
  SessionID=res.headers.get('set-cookie').replace('SessionID=','');

  return fetch('http://192.168.8.1/api/webserver/token',{headers:{SessionID}})

}).then(res=>res.text()).then(tokenXml=>{
//<?xml version="1.0" encoding="UTF-8"?><response><token>EUmPsy7Ap0zcjn0aM0DxdFC6bmX70jRk6S0XQU6UfKWPhgKZ8IqMQNZzqOMswXpQ</token></response>

  let __RequestVerificationToken=extractToken(convert.xml2js(tokenXml,{compact:true})).substr(32);
  console.log(token);
  let scram = CryptoJS.SCRAM();
  let firstnonce = scram.nonce().toString();
  let firstPostData=
        {
          request:{
            username,
            firstnonce,
            mode
            }
        };


  var firstXml=`<?xml version:"1.0" encoding="UTF-8"?>${convert.json2xml(firstPostData)}`;
  console.log(firstXml);
  //<?xml version:"1.0" encoding="UTF-8"?><request><username>admin</username><firstnonce>ed3f54707975f7d825d934b6322b3efb68c7e1bb93a970c593dc67d8df9e24c2</firstnonce><mode>1</mode></request>
  return fetch('http://192.168.8.1/api/user/challenge_login',{
      method: 'POST',
      body: firstXml,
      compress:true,
      headers:
      {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        __RequestVerificationToken,
        SessionID
      }
  })
}).then(res=>res.text()).then(res=>console.log(res))


//<?xml version:"1.0" encoding="UTF-8"?><request><clientproof>c051cf90cee3cbbe36d632d23f16f76c05ca84382b99acf4798a04ab570c20e1</clientproof><finalnonce>ed3f54707975f7d825d934b6322b3efb68c7e1bb93a970c593dc67d8df9e24c2JHYnpz21wSdGl8tekXLO06JDzX0FkqVa</finalnonce></request>
//SessionID=res.headers.get('set-cookie');
