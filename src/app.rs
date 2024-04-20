use egui::TextBuffer;
/// We derive Deserialize/Serialize so we can persist app state on shutdown.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(default)] // if we add new fields, give them default values when deserializing old state
pub struct TemplateApp {
    // Example stuff:
    #[serde(skip)] // This how you opt-out of serialization of a field
    owner_script_hash: String,
    price_base: u32,
    price_pow: u32,
    mode: u16,
    amount: u64,
    encoded_string: String,
    encode_status: String,
    decode_status: String,
    last_status: bool,
    ckb_cap: f64,
}

impl Default for TemplateApp {
    fn default() -> Self {
        Self {
            // Example stuff:
            owner_script_hash: "0x00000000000000000000000000000000".to_owned(),
            mode: 0,
            price_base: 1,
            price_pow: 0,
            amount: 1,
            encoded_string: "0x".to_owned(),
            encode_status: "".to_owned(),
            decode_status: "".to_owned(),
            last_status: true,
            ckb_cap: 0.0,
        }
    }
}

impl TemplateApp {
    /// Called once before the first frame.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // This is also where you can customize the look and feel of egui using
        // `cc.egui_ctx.set_visuals` and `cc.egui_ctx.set_fonts`.

        // Load previous app state (if any).
        // Note that you must enable the `persistence` feature for this to work.
        if let Some(storage) = cc.storage {
            return eframe::get_value(storage, eframe::APP_KEY).unwrap_or_default();
        }

        Default::default()
    }

    fn decode(&mut self) -> Result<(), DexHelperError> {
        let args = self
            .encoded_string
            .strip_prefix("0x")
            .unwrap_or(&self.encoded_string);
        if args.len() != 42 {
            return Err(DexHelperError::ArgsLenError);
        }
        let mode_bytes = [
            u8::from_str_radix(args.char_range(0..1), 16).unwrap(),
            u8::from_str_radix(args.char_range(1..2), 16).unwrap(),
        ];
        let mode = u16::from_le_bytes(mode_bytes);
        if mode > 2 {
            return Err(DexHelperError::ModeTooBig);
        }
        self.mode = mode;
        let owner_script_hash = &args[2..34];
        self.owner_script_hash = format!("0x{}", owner_script_hash);
        println!("mode: {}, owner_script_hash: {}", mode, owner_script_hash);
        Ok(())
    }

    fn encode(&mut self) -> Result<String, DexHelperError> {
        let mut encoded = "0x".to_owned();
        let mode_bytes = self.mode.to_le_bytes();
        encoded.push_str(&format!("{:x}{:x}", mode_bytes[0], mode_bytes[1]));
        let owner_script_hash = self
            .owner_script_hash
            .strip_prefix("0x")
            .unwrap_or(self.owner_script_hash.as_str());
        if owner_script_hash.len() != 32 {
            return Err(DexHelperError::LockScriptHashError);
        }

        encoded.push_str(owner_script_hash);
        let price_bytes = self.price_base.to_le_bytes();
        encoded.push_str(&format!(
            "{:02x}",
            u16::from_ne_bytes([price_bytes[0], price_bytes[1]])
        ));
        encoded.push_str(&format!(
            "{:02x}",
            u16::from_ne_bytes([price_bytes[1], price_bytes[2]])
        ));

        let price_pow_bytes = self.price_pow.to_le_bytes();
        encoded.push_str(&format!(
            "{:02x}",
            u16::from_ne_bytes([price_pow_bytes[0], price_pow_bytes[1]])
        ));

        encoded.push_str(&format!(
            "{:02x}",
            u16::from_ne_bytes([price_pow_bytes[1], price_pow_bytes[2]])
        ));

        Ok(encoded)
    }
}

impl eframe::App for TemplateApp {
    /// Called by the frame work to save state before shutdown.
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, eframe::APP_KEY, self);
    }

    /// Called each time the UI needs repainting, which may be many times per second.
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Put your widgets into a `SidePanel`, `TopBottomPanel`, `CentralPanel`, `Window` or `Area`.
        // For inspiration and more examples, go to https://emilk.github.io/egui

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            // The top panel is often a good place for a menu bar:

            egui::menu::bar(ui, |ui| {
                // NOTE: no File->Quit on web pages!
                let is_web = cfg!(target_arch = "wasm32");
                if !is_web {
                    ui.menu_button("File", |ui| {
                        if ui.button("Quit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.add_space(16.0);
                }

                egui::widgets::global_dark_light_mode_buttons(ui);
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {

        egui::ScrollArea::vertical().show(ui, |ui| {

            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    // The central panel the region left after adding TopPanel's and SidePanel's
                    ui.heading("Dex Lock Args Encode/Decode Helper");

                    ui.horizontal(|ui| {
                        ui.label("Mode");
                        ui.add(egui::widgets::Slider::new(&mut self.mode, 0..=2));
                        match self.mode {
                            0 => {
                                ui.label(egui::RichText::new("UDT compatible mode").color(egui::Color32::YELLOW).background_color(egui::Color32::GRAY));
                            }
                            1 => {
                                ui.label(egui::RichText::new("Restrict Mode, Can't modify Data/Type during trade.").color(egui::Color32::YELLOW).background_color(egui::Color32::GRAY));
                            }
                            2 => {
                                ui.label(egui::RichText::new("Partial Restrict Mode, Can't modify Type during trade, but Data can.").color(egui::Color32::YELLOW).background_color(egui::Color32::GRAY));
                            }
                            _ => {}
                        }
                    });

                    if self.mode == 0 {
                        ui.horizontal(|ui| {
                            ui.label("Amount");
                            ui.add(egui::widgets::Slider::new(&mut self.amount, 1..=u64::MAX));
                            ui.separator();
                            ui.label("Data: ");
                            let fixed = (self.amount as u128).to_le_bytes();
                            let data = hex::encode(fixed);

                            ui.label(egui::RichText::new(format!("0x{}", data)));
                        });
                    }

                    ui.horizontal(|ui| {
                        ui.label("Owner LockScript Hash");
                        ui.add_sized(
                            ui.available_size() / 2.5,
                            egui::TextEdit::singleline(&mut self.owner_script_hash),
                        );
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Encode").clicked() {
                            match self.encode() {
                                Ok(encoded) => {
                                    self.encoded_string = encoded;
                                    self.encode_status = "".to_string();
                                }
                                Err(e) => match e {
                                    DexHelperError::LockScriptHashError => {
                                        self.encode_status =
                                            "LockScript Hash Len Error!!!Must Be 32 bytes!"
                                                .to_string();
                                    }
                                    _ => {
                                        unreachable!();
                                    }
                                },
                            }
                        }
                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| {
                                o.copied_text = self.owner_script_hash.clone();
                            });
                            self.encode_status = "Owner Script Hash Copied".to_string();
                        }
                    });

                    ui.label(egui::RichText::new(&self.encode_status).color(
                        if self.encode_status.is_empty() {
                            egui::Color32::WHITE
                        } else {
                            egui::Color32::RED
                        },
                    ));
                    ui.label("Price Base:");
                    ui.add(egui::widgets::Slider::new(
                        &mut self.price_base,
                        1..=u32::MAX,
                    ));
                    ui.label("Price Pow:");
                    ui.add(egui::widgets::Slider::new(
                        &mut self.price_pow,
                        0..=15,
                    ));
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.heading("Output");
                    ui.horizontal(|ui| {
                        ui.heading("Encoded Args");
                        ui.add_sized(
                            ui.available_size(),
                            egui::TextEdit::singleline(&mut self.encoded_string),
                        );
                    });

                    let color = if self.last_status {
                        egui::Color32::GREEN
                    } else {
                        egui::Color32::RED
                    };
                    ui.horizontal(|ui| {
                        if ui
                            .button("Decode")
                            .on_hover_text("Decode the encoded args")
                            .clicked()
                        {
                            let result: Result<(), DexHelperError> = self.decode();
                            self.last_status = result.is_ok();

                            if result.is_err() {
                                self.decode_status = "Decode Error!!!".to_string();
                                match result.unwrap_err() {
                                    DexHelperError::ModeTooBig => {
                                        self.decode_status.push_str("Mode too big!");
                                    }
                                    DexHelperError::ArgsLenError => {
                                        self.decode_status.push_str(
                                            format!(
                                                "Args Len Error!!!Must Be 42 bytes, but got {}",
                                                self.encoded_string
                                                    .strip_prefix("0x")
                                                    .unwrap_or(self.encoded_string.as_str())
                                                    .len()
                                            )
                                            .as_str(),
                                        );
                                    }
                                    _ => {}
                                }
                            } else {
                                self.decode_status = "Okay".to_string();
                            }
                        }

                        if ui.button("Copy").clicked() {
                            ui.output_mut(|o| {
                                o.copied_text = self.encoded_string.clone();
                            });
                            self.decode_status = "Copied".to_string();
                        }
                    });

                    ui.label(egui::RichText::new(&self.decode_status).color(color));
                })
            });
            ui.separator();
            current_contract_info(ui, &self.encoded_string);
            ui.separator();
            current_encode_method(ui, self);
            ui.separator();
            how_to_build_transaction(ui, self);
            powered_by_egui_and_eframe(ui);
        });
        });
    }
}
enum DexHelperError {
    LockScriptHashError,
    ModeTooBig,
    ArgsLenError,
}

fn current_encode_method(ui: &mut egui::Ui, app: &mut TemplateApp) {
    ui.horizontal(|ui| {
        ui.heading(
            egui::RichText::new("Please check current encode method")
                .color(egui::Color32::LIGHT_YELLOW),
        );
        ui.heading(
            egui::RichText::new("(using current example):").color(egui::Color32::LIGHT_BLUE),
        );
    });
    ui.horizontal(|ui| {
        ui.label("First 2 bytes(le_bytes): mode ");
        ui.separator();
        ui.label(egui::RichText::new(format!(
            "{}.to_le_bytes() = {:?}",
            app.mode,
            app.mode.to_le_bytes()
        )));
        if ui
            .label(
                egui::RichText::new(format!(
                    "0x{:x}{:x}",
                    app.mode.to_le_bytes()[0],
                    app.mode.to_le_bytes()[1]
                ))
                .color(egui::Color32::LIGHT_GREEN)
                .background_color(egui::Color32::BLACK),
            )
            .on_hover_text("Click to copy")
            .clicked()
        {
            ui.output_mut(|o| {
                o.copied_text = format!(
                    "0x{:x}{:x}",
                    app.mode.to_le_bytes()[0],
                    app.mode.to_le_bytes()[1]
                );
            });
        }
    });

    ui.horizontal(|ui| {
        let original_space = ui.spacing().item_spacing.x;
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("Next ");
        ui.label(egui::RichText::new("32").color(egui::Color32::LIGHT_YELLOW));
        ui.label(" bytes: owner_script_hash ");

        ui.spacing_mut().item_spacing.x = original_space;
        ui.separator();
        if ui
            .label(
                egui::RichText::new(app.owner_script_hash.clone())
                    .color(egui::Color32::LIGHT_GREEN)
                    .background_color(egui::Color32::BLACK),
            )
            .on_hover_text("Click to copy")
            .clicked()
        {
            ui.output_mut(|o| {
                o.copied_text = app.owner_script_hash.clone();
            });
        }
    });

    ui.horizontal(|ui| {
        ui.label("Next 4 bytes(le_bytes): price_base ");
        ui.separator();
        ui.label(egui::RichText::new(format!(
            "{}.to_le_bytes() = {:?}",
            app.price_base,
            app.price_base.to_le_bytes()
        )));

        let price_bytes = app.price_base.to_le_bytes();

        if ui
            .label(
                egui::RichText::new(format!(
                    "0x{:02x}{:02x}",
                    u16::from_ne_bytes([price_bytes[0], price_bytes[1]]),
                    u16::from_ne_bytes([price_bytes[1], price_bytes[2]])
                ))
                .color(egui::Color32::LIGHT_GREEN)
                .background_color(egui::Color32::BLACK),
            )
            .on_hover_text("Click to copy")
            .clicked()
        {
            ui.output_mut(|o| {
                o.copied_text = format!(
                    "0x{:02x}{:02x}",
                    u16::from_ne_bytes([price_bytes[0], price_bytes[1]]),
                    u16::from_ne_bytes([price_bytes[1], price_bytes[2]])
                );
            });
        }
    });

    ui.horizontal(|ui| {
        ui.label("Last 4 bytes(le_bytes): price_pow ");
        ui.separator();
        ui.label(egui::RichText::new(format!(
            "{}.to_le_bytes() = {:?}",
            app.price_pow,
            app.price_pow.to_le_bytes()
        )));

        let price_pow_bytes = app.price_pow.to_le_bytes();
        if ui
            .label(
                egui::RichText::new(format!(
                    "0x{:02x}{:02x}",
                    u16::from_ne_bytes([price_pow_bytes[0], price_pow_bytes[1]]),
                    u16::from_ne_bytes([price_pow_bytes[1], price_pow_bytes[2]])
                ))
                .color(egui::Color32::LIGHT_GREEN)
                .background_color(egui::Color32::BLACK),
            )
            .on_hover_text("Click to copy")
            .clicked()
        {
            ui.output_mut(|o| {
                o.copied_text = format!(
                    "0x{:02x}{:02x}",
                    u16::from_ne_bytes([price_pow_bytes[0], price_pow_bytes[1]]),
                    u16::from_ne_bytes([price_pow_bytes[1], price_pow_bytes[2]])
                )
            });
        }
    });

    ui.horizontal(|ui| {
        ui.label("Total price will be:");
        ui.separator();
        let total = match app.mode {
            0 => app.amount as u128 * app.price_base as u128 * 10u128.pow(app.price_pow),
            _ => app.price_base as u128 * 10u128.pow(app.price_pow),
        };
        app.ckb_cap = total as f64 / 1000_0000.0;

        if app.mode == 0 {
            ui.label(egui::RichText::new(format!(
                "{} * {} * 10^{} = {} Shannons",
                app.amount, app.price_base, app.price_pow, total,
            )));
        } else {
            ui.label(egui::RichText::new(format!(
                "{} * 10^{} = {} Shannons",
                app.price_base, app.price_pow, total,
            )));
        }
        ui.separator();
        ui.label(egui::RichText::new(format!("{} CKB", app.ckb_cap)));
        let _total_le = total.to_le_bytes();
    });
}

fn current_contract_info(ui: &mut egui::Ui, encoded_args: &str) {
    ui.horizontal(|ui| {
        ui.text_style_height(&egui::style::TextStyle::Heading);
        ui.heading("Current Contract: ");
        ui.hyperlink_to(egui::RichText::heading("transaction".into()), "https://pudge.explorer.nervos.org/transaction/0x9cd3316ab4306deacb8cc6c22180c9ad626ffa0ddbc5eb84fdd078e541815db2");
    });
    ui.vertical(|ui| {
        ui.heading("How to Set Cell's lock: ");
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.label(egui::RichText::new("codeHash:").color(egui::Color32::LIGHT_BLUE));
            if ui
                .label(
                    egui::RichText::new(
                        "0xcc62edd5c460ceda11b2b473102ac384e774491a4dfca267ea39af2075d2f70f",
                    )
                    .color(egui::Color32::LIGHT_GREEN)
                    .background_color(egui::Color32::BLACK),
                )
                .on_hover_text("Click to copy codeHash")
                .clicked()
            {
                // copy code_hash
                ui.output_mut(|o| {
                    o.copied_text =
                        "0xcc62edd5c460ceda11b2b473102ac384e774491a4dfca267ea39af2075d2f70f"
                            .to_owned()
                })
            };
        });
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.label(egui::RichText::new("hashType:").color(egui::Color32::LIGHT_BLUE));
            ui.label(
                egui::RichText::new("data1")
                    .color(egui::Color32::LIGHT_GREEN)
                    .background_color(egui::Color32::BLACK),
            );
        });
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 10.0;
            ui.label(egui::RichText::new("args:").color(egui::Color32::LIGHT_BLUE));
            if ui
                .label(
                    egui::RichText::new(encoded_args)
                        .color(egui::Color32::LIGHT_GREEN)
                        .background_color(egui::Color32::BLACK),
                )
                .on_hover_text("Click to copy args")
                .clicked()
            {
                // copy code_hash
                ui.output_mut(|o| o.copied_text = encoded_args.to_owned());
            };
        });
    });
    ui.separator();
    ui.vertical(|ui| {
        ui.text_style_height(&egui::style::TextStyle::Heading);
        ui.heading(
            egui::RichText::new("Ensure to set CellDeps contains: ").color(egui::Color32::BROWN),
        );
        ui.label(
            egui::RichText::new("- Original Lock's script dep").color(egui::Color32::LIGHT_YELLOW),
        );
        ui.label(
            egui::RichText::new("- Dex Lock's script dep(showed as bellow)")
                .color(egui::Color32::LIGHT_YELLOW),
        );
        let text = r#"{
           "out_point":{
              "tx_hash":"0x9cd3316ab4306deacb8cc6c22180c9ad626ffa0ddbc5eb84fdd078e541815db2",
              "index":"0x0"
           },
           "dep_type":"code"
}"#;
        ui.label(
            egui::RichText::new(text)
                .color(egui::Color32::LIGHT_GREEN)
                .background_color(egui::Color32::BLACK),
        )
        .highlight()
        .on_hover_text("Click to copy");
    });
}

fn how_to_build_transaction(ui: &mut egui::Ui, app: &TemplateApp) {
    ui.label(
        egui::RichText::new("Bellow is instructions about how to build transaction:")
            .color(egui::Color32::LIGHT_YELLOW),
    );
    ui.horizontal(|ui| {
        ui.vertical_centered_justified(|ui|{
            ui.horizontal(|ui| {
                ui.label("1. If you want to make an offer:");
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Input:").color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new("  Orignal Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("    - Lock: <USER_DEFINED> (Lock.hash = {})", app.owner_script_hash)).color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("  <Other Cells...>").color(egui::Color32::LIGHT_GREEN));
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Output:").color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new("  Dex Locked Asset Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED> (Should be same with original)").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("    - Lock:").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("            codeHash: 0xcc62edd5c460ceda11b2b473102ac384e774491a4dfca267ea39af2075d2f70f").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("            args: {}", app.encoded_string)).color(egui::Color32::DEBUG_COLOR));
                    ui.label(egui::RichText::new("            hashType: data1").color(egui::Color32::LIGHT_YELLOW));
                });
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("2. If you want to take an offer:");
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Input:").color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new("  Dex Locked Asset Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Capacity: N").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("    - Lock:").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("            codeHash: 0xcc62edd5c460ceda11b2b473102ac384e774491a4dfca267ea39af2075d2f70f").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("            args: {}", app.encoded_string)).color(egui::Color32::DEBUG_COLOR));
                    ui.label(egui::RichText::new("            hashType: data1").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("  <Other Cells...(Payment Input)>").color(egui::Color32::LIGHT_GREEN));
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Output:").color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new("  Bought Asset Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>  (Should be same with original)").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("    - Lock: <USER_DEFINED> (Buyer's lock)").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("  Orignal Owner Peyment Receive Cell:").color(egui::Color32::LIGHT_GREEN));
                    ui.label(egui::RichText::new(format!("    - Capacity: N + {} CKB", app.ckb_cap)).color(egui::Color32::GREEN));
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("    - Lock: <USER_DEFINED> (Lock.hash = {})", app.owner_script_hash)).color(egui::Color32::LIGHT_YELLOW));
                });
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("3. If you want to cancel an offer:");
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Input:").color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new("  Dex Locked Asset Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED> (Should be same with original)").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("    - Lock:").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("            codeHash: 0xcc62edd5c460ceda11b2b473102ac384e774491a4dfca267ea39af2075d2f70f").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("            args: {}", app.encoded_string)).color(egui::Color32::DEBUG_COLOR));
                    ui.label(egui::RichText::new("            hashType: data1").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("  Orignal Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("    - Lock: <USER_DEFINED>\n(Lock.hash = {})", app.owner_script_hash)).color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("  <Other Cells...>").color(egui::Color32::LIGHT_GREEN));
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.label(egui::RichText::new("Output:").color(egui::Color32::WHITE));
                    ui.label(egui::RichText::new("  Bought Asset Cell:").color(egui::Color32::LIGHT_GREEN));
                    if app.mode == 0 {
                        ui.label(egui::RichText::new(format!("    - Data: 0x{}", hex::encode((app.amount as u128).to_le_bytes()))).color(egui::Color32::LIGHT_YELLOW));
                    }
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("    - Lock: <USER_DEFINED> (Buyer's lock)").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new("  Orignal Owner Peyment Receive Cell:").color(egui::Color32::LIGHT_GREEN));
                    ui.label(egui::RichText::new("    - Type: <USER_DEFINED>").color(egui::Color32::LIGHT_YELLOW));
                    ui.label(egui::RichText::new(format!("    - Lock: <USER_DEFINED>\n(Lock.hash = {})", app.owner_script_hash)).color(egui::Color32::LIGHT_YELLOW));
                });
            });
        });
    });
}

fn powered_by_egui_and_eframe(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 0.0;
        ui.label("Powered by ");
        ui.hyperlink_to("egui", "https://github.com/emilk/egui");
        ui.label(" and ");
        ui.hyperlink_to(
            "eframe",
            "https://github.com/emilk/egui/tree/main/crates/eframe",
        );
        ui.label(".");
    });
}
