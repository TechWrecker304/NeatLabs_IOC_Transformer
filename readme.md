# NeatLabs IOC Transformer Pro

The NeatLabs IOC Transformer Pro is a powerful and user-friendly program designed to assist threat hunters and security professionals in transforming Indicators of Compromise (IOCs) into actionable rule formats. With this program, you can easily generate rules for various security tools and platforms, such as Splunk, Suricata, Yara, Snort, and Sigma.

## Features

- **IOC Input**: Enter IOCs manually or load them from a file. The program supports various IOC types, including IP addresses, domain names, and hashes.
- **Rule Generation**: Generate rules based on the entered IOCs and the selected rule type. The program provides support for Splunk, Suricata, Yara, Snort, and Sigma rule formats.
- **Rule Customization**: Customize the generated rules by selecting the desired severity level (low, medium, or high).
- **Rule Description**: View a detailed description of each rule type to understand its purpose, composition, and suitable data types.
- **IOC Validation**: The program performs validation checks on the entered IOCs to ensure they are in the correct format. Invalid IOCs are flagged, and appropriate recommendations are provided.
- **Bulk Processing**: Generate rules for multiple IOCs simultaneously, making the process efficient and time-saving.
- **Rule Preview**: Preview the generated rules before saving or copying them, allowing you to review and verify the output.
- **Rule Export**: Save the generated rules to a file or copy them to the clipboard for easy integration into your security tools and workflows.
- **IOC Deduplication**: The program automatically removes duplicate IOCs from the input, ensuring that only unique IOCs are processed.
- **Rule Statistics**: View statistics about the generated rules, including the total number of rules and a breakdown by rule type.
- **IOC Sources**: Access a curated list of dependable sites for obtaining IOCs directly from the program. Simply select a source from the dropdown menu, and the program will launch your default web browser and navigate to the chosen site.
- **User-Friendly Interface**: The program features an intuitive and visually appealing graphical user interface (GUI) that enhances the user experience and makes rule generation a breeze.

## Installation

1. Clone the repository or download the source code files.
2. Ensure you have Python 3.x installed on your system.
3. Install the required dependencies by running the following command:
   ```
   pip install tkinter webbrowser
   ```
4. Run the program by executing the following command:
   ```
   python ioc_transformer.py
   ```

## Usage

1. Launch the NeatLabs IOC Transformer Pro program.
2. Enter the IOCs you want to transform in the "Enter IOCs" section. You can enter them manually, one per line, or load them from a file using the "Load IOCs from File" button.
3. Select the desired rule type from the "Select Rule Type" dropdown menu. The available options are Splunk, Suricata, Yara, Snort, and Sigma.
4. Choose the severity level for the generated rules using the radio buttons (low, medium, or high).
5. Click the "Generate Rules" button to generate the rules based on the entered IOCs and selected options.
6. Review the generated rules in the "Generated Rules" section. You can preview the rules before saving or copying them.
7. Use the "Copy Rules" button to copy the generated rules to the clipboard, or click the "Save Rules" button to save them to a file.
8. If you want to clear the entered IOCs or generated rules, use the "Clear IOCs" and "Clear Rules" buttons, respectively.
9. Access reliable IOC sources by selecting a site from the "IOC Sources" dropdown menu. The program will launch your default web browser and navigate to the selected site.
10. View the rule statistics in the "Rule Statistics" section to get insights into the total number of rules and the breakdown by rule type.

## Contributing

Contributions to the NeatLabs IOC Transformer Pro program are welcome! If you have any ideas, suggestions, or bug reports, please open an issue on the GitHub repository. If you'd like to contribute code improvements or new features, feel free to submit a pull request.

## License

This program is released under the [MIT License](LICENSE). You are free to use, modify, and distribute the code for both commercial and non-commercial purposes.

## Acknowledgements

The NeatLabs IOC Transformer Pro program was developed by Tech-Wrecker304 as a tool to assist the cybersecurity community in generating actionable rules from IOCs. We would like to thank the open-source community for their valuable contributions and the developers of the various security tools and platforms supported by this program.

## Contact

If you have any questions, feedback, or suggestions regarding the NeatLabs IOC Transformer Pro program, please feel free to contact us. We appreciate your input and strive to continuously improve the program to meet the needs of the cybersecurity community.

Happy threat hunting and stay secure!
