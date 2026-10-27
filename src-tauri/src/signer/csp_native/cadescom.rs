#![deny(unsafe_code)]

#[allow(unsafe_code)]
mod ffi {
    use std::{mem::ManuallyDrop, ptr};
    use windows::core::{Interface, BSTR, GUID, PCWSTR};
    use windows::Win32::Globalization::LOCALE_USER_DEFAULT;
    use windows::Win32::System::Com::{
        CLSIDFromProgID, CoCreateInstance, CoInitializeEx, CoUninitialize, IDispatch,
        CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, DISPATCH_FLAGS, DISPATCH_METHOD,
        DISPATCH_PROPERTYGET, DISPATCH_PROPERTYPUT, DISPATCH_PROPERTYPUTREF, DISPPARAMS,
    };
    use windows::Win32::System::Ole::DISPID_PROPERTYPUT;
    use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_BSTR, VT_I2, VT_I4, VT_UI4};

    struct Apartment;
    impl Apartment {
        fn initialize() -> Result<Self, String> {
            let result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
            if result.is_err() {
                return Err(format!(
                    "Не удалось инициализировать COM apartment: HRESULT 0x{:08X}",
                    result.0 as u32
                ));
            }
            Ok(Self)
        }
    }
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() }
        }
    }

    fn create(prog_id: &str) -> Result<IDispatch, String> {
        let display_name = prog_id.to_owned();
        let prog_id = prog_id
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let clsid = unsafe { CLSIDFromProgID(PCWSTR(prog_id.as_ptr())) }
            .map_err(|error| format!("Не зарегистрирован COM объект {display_name}: {error}"))?;
        let unknown = unsafe {
            CoCreateInstance::<_, windows::core::IUnknown>(&clsid, None, CLSCTX_INPROC_SERVER)
        }
        .map_err(|error| format!("Не удалось создать COM объект {display_name}: {error}"))?;
        unknown.cast::<IDispatch>().map_err(|error| {
            format!("COM объект {display_name} не поддерживает IDispatch: {error}")
        })
    }

    pub(super) fn probe() -> Result<(), String> {
        let _apartment = Apartment::initialize()?;
        let _signed_data = create("CAdESCOM.CadesSignedData")?;
        Ok(())
    }

    fn dispid(object: &IDispatch, name: &str) -> Result<i32, String> {
        let name = name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let name_ptr = PCWSTR(name.as_ptr());
        let mut id = 0;
        unsafe {
            object.GetIDsOfNames(&GUID::zeroed(), &name_ptr, 1, LOCALE_USER_DEFAULT, &mut id)
        }
        .map_err(|error| format!("CAdESCOM не предоставляет метод/свойство {name:?}: {error}"))?;
        Ok(id)
    }

    fn call(
        object: &IDispatch,
        name: &str,
        flags: DISPATCH_FLAGS,
        arguments: &mut [VARIANT],
    ) -> Result<VARIANT, String> {
        let id = dispid(object, name)?;
        let parameters = DISPPARAMS {
            rgvarg: if arguments.is_empty() {
                ptr::null_mut()
            } else {
                arguments.as_mut_ptr()
            },
            rgdispidNamedArgs: ptr::null_mut(),
            cArgs: arguments.len() as u32,
            cNamedArgs: 0,
        };
        let mut result = VARIANT::default();
        unsafe {
            object.Invoke(
                id,
                &GUID::zeroed(),
                LOCALE_USER_DEFAULT,
                flags,
                &parameters,
                Some(&mut result),
                None,
                None,
            )
        }
        .map_err(|error| format!("Ошибка вызова CAdESCOM.{name}: {error}"))?;
        Ok(result)
    }

    fn get(object: &IDispatch, name: &str) -> Result<VARIANT, String> {
        call(object, name, DISPATCH_PROPERTYGET, &mut [])
    }

    fn invoke(
        object: &IDispatch,
        name: &str,
        mut arguments: Vec<VARIANT>,
    ) -> Result<VARIANT, String> {
        call(object, name, DISPATCH_METHOD, &mut arguments)
    }

    fn put(
        object: &IDispatch,
        name: &str,
        mut value: VARIANT,
        by_reference: bool,
    ) -> Result<(), String> {
        let id = dispid(object, name)?;
        let mut named_id = DISPID_PROPERTYPUT;
        let parameters = DISPPARAMS {
            rgvarg: &mut value,
            rgdispidNamedArgs: &mut named_id,
            cArgs: 1,
            cNamedArgs: 1,
        };
        let invoke_put = |flag| unsafe {
            object.Invoke(
                id,
                &GUID::zeroed(),
                LOCALE_USER_DEFAULT,
                flag,
                &parameters,
                None,
                None,
                None,
            )
        };
        let result = if by_reference {
            // Some CAdESCOM builds expose interface-valued properties through
            // PROPERTYPUT only, while others accept the Automation-standard PUTREF.
            invoke_put(DISPATCH_PROPERTYPUTREF).or_else(|_| invoke_put(DISPATCH_PROPERTYPUT))
        } else {
            invoke_put(DISPATCH_PROPERTYPUT)
        };
        result.map_err(|error| format!("Не удалось установить CAdESCOM.{name}: {error}"))
    }

    fn as_dispatch(value: &VARIANT) -> Result<IDispatch, String> {
        IDispatch::try_from(value)
            .map_err(|error| format!("CAdESCOM вернул неожиданный тип объекта: {error}"))
    }

    fn as_string(value: &VARIANT) -> Result<String, String> {
        if value.vt() != VT_BSTR {
            return Err("CAdESCOM вернул значение не типа BSTR".to_owned());
        }
        let bstr = unsafe { ManuallyDrop::clone(&value.Anonymous.Anonymous.Anonymous.bstrVal) };
        Ok(String::from_utf16_lossy(&bstr))
    }

    fn as_integer(value: &VARIANT) -> Result<i32, String> {
        unsafe {
            match value.vt() {
                VT_I2 => Ok(value.Anonymous.Anonymous.Anonymous.iVal as i32),
                VT_I4 => Ok(value.Anonymous.Anonymous.Anonymous.lVal),
                VT_UI4 => Ok(value.Anonymous.Anonymous.Anonymous.ulVal as i32),
                _ => Err("CAdESCOM вернул значение не целого типа".to_owned()),
            }
        }
    }

    fn select_certificate(store: &IDispatch, certificate_id: &str) -> Result<IDispatch, String> {
        let certificates = as_dispatch(&get(store, "Certificates")?)?;
        let count = as_integer(&get(&certificates, "Count")?)?;
        let wanted = certificate_id
            .rsplit_once(':')
            .map(|(_, serial)| serial)
            .ok_or_else(|| "Неверный идентификатор выбранного сертификата".to_owned())?;
        let wanted_reverse = reverse_hex_bytes(wanted);
        for index in 1..=count {
            // ICertificates.Item is a parameterized property getter, not an IDispatch method.
            let cert_variant = call(
                &certificates,
                "Item",
                DISPATCH_PROPERTYGET,
                &mut [VARIANT::from(index)],
            )?;
            let certificate = as_dispatch(&cert_variant)?;
            let serial = as_string(&get(&certificate, "SerialNumber")?)?;
            let serial = serial
                .chars()
                .filter(|character| character.is_ascii_hexdigit())
                .collect::<String>();
            if serial.eq_ignore_ascii_case(wanted) || serial.eq_ignore_ascii_case(&wanted_reverse) {
                let has_key = get(&certificate, "HasPrivateKey")
                    .map(|v| {
                        if v.vt() == VT_BOOL {
                            unsafe { v.Anonymous.Anonymous.Anonymous.boolVal.0 != 0 }
                        } else {
                            as_integer(&v).unwrap_or(0) != 0
                        }
                    })
                    .unwrap_or(false);
                if !has_key {
                    // HasPrivateKey may be false until CAdESCOM explicitly binds the
                    // certificate to a CSP container. FindPrivateKey performs that lookup.
                    invoke(&certificate, "FindPrivateKey", vec![]).map_err(|error| {
                        format!("CAdESCOM не смог связать сертификат с закрытым ключом: {error}")
                    })?;
                }
                return Ok(certificate);
            }
        }
        Err("Выбранный сертификат не найден в CAdESCOM CurrentUser store; проверьте установку CryptoPro ЭЦП SDK.".to_owned())
    }

    fn reverse_hex_bytes(hex: &str) -> String {
        let mut bytes = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| [pair[0], pair[1]])
            .collect::<Vec<_>>();
        bytes.reverse();
        bytes.into_iter().flatten().map(char::from).collect()
    }

    pub(super) fn sign(
        request: crate::signer::SignRequest,
    ) -> Result<crate::signer::SignResult, crate::signer::SignerError> {
        sign_inner(request).map_err(crate::signer::SignerError::Signing)
    }

    fn sign_inner(
        request: crate::signer::SignRequest,
    ) -> Result<crate::signer::SignResult, String> {
        let _apartment = Apartment::initialize()?;
        let content = std::fs::read(&request.input_path)
            .map_err(|error| format!("Не удалось прочитать исходный файл: {error}"))?;
        let store = create("CAdESCOM.Store")?;
        // CAPICOM_CURRENT_USER_STORE=2; Open accepts additional parameters as optional.
        invoke(&store, "Open", vec![VARIANT::from(2i32)])?;
        let certificate = select_certificate(&store, &request.certificate_id)?;
        let signer = create("CAdESCOM.CPSigner")?;
        put(&signer, "Certificate", VARIANT::from(certificate), true)?;
        let signed_data = create("CAdESCOM.CadesSignedData")?;
        // CryptoPro documents CADESCOM_BASE64_TO_BINARY=1 for exact binary file content.
        put(&signed_data, "ContentEncoding", VARIANT::from(1i32), false)?;
        put(
            &signed_data,
            "Content",
            VARIANT::from(BSTR::from(base64_encode(&content))),
            false,
        )?;
        let signature_variant = invoke(
            &signed_data,
            "SignCades",
            vec![
                VARIANT::from(0i32), // CAPICOM_ENCODE_BASE64. Convert to DER ourselves if requested.
                VARIANT::from(request.detached),
                VARIANT::from(1i32), // CADESCOM_CADES_BES
                VARIANT::from(signer),
            ],
        )?;
        let signature_b64 = as_string(&signature_variant)?;
        let output = if request.base64 {
            signature_b64.into_bytes()
        } else {
            decode_base64(&signature_b64)?
        };
        let output_path = std::path::PathBuf::from(&request.output_path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)
            .map_err(|error| {
                format!(
                    "Не удалось создать файл результата без перезаписи ({}): {error}",
                    output_path.display()
                )
            })?;
        use std::io::Write;
        if let Err(error) = file.write_all(&output) {
            drop(file);
            let _ = std::fs::remove_file(&output_path);
            return Err(format!("Не удалось записать результат CAdES-BES: {error}"));
        }
        Ok(crate::signer::SignResult {
            output_path: output_path.display().to_string(),
            bytes_written: output.len(),
        })
    }

    fn base64_encode(bytes: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
        for chunk in bytes.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            output.push(TABLE[(a >> 2) as usize] as char);
            output.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
            output.push(if chunk.len() > 1 {
                TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
            } else {
                '='
            });
            output.push(if chunk.len() > 2 {
                TABLE[(c & 63) as usize] as char
            } else {
                '='
            });
        }
        output
    }

    fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
        let mut output = Vec::with_capacity(input.len() * 3 / 4);
        let mut chunk = [0u8; 4];
        let mut used = 0;
        for byte in input.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
            chunk[used] = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' => 64,
                _ => return Err("CAdESCOM вернул некорректную Base64 подпись".to_owned()),
            };
            used += 1;
            if used == 4 {
                output.push((chunk[0] << 2) | (chunk[1] >> 4));
                if chunk[2] != 64 {
                    output.push((chunk[1] << 4) | (chunk[2] >> 2));
                }
                if chunk[3] != 64 {
                    output.push((chunk[2] << 6) | chunk[3]);
                }
                used = 0;
            }
        }
        if used != 0 {
            return Err("CAdESCOM вернул Base64 подпись с неверной длиной".to_owned());
        }
        Ok(output)
    }
}

pub fn sign_file(
    request: crate::signer::SignRequest,
) -> Result<crate::signer::SignResult, crate::signer::SignerError> {
    ffi::sign(request)
}

pub fn probe() -> Result<(), String> {
    ffi::probe()
}
