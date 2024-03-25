//
//  Loggers.swift
//
//
//  Created by Bryan Montz on 12/10/23.
//

import Foundation
import OSLog

enum Loggers {
    private static let subsystem = "NIP44"

    static let keypairs = Logger(subsystem: Loggers.subsystem, category: "Keypairs")
}
